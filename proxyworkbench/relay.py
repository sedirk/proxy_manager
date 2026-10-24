"""Opt-in loopback TCP proxy. No system proxy, routes, TUN, or TLS interception.

Each channel has its own listener and configuration identifier. HTTP uses one
request per connection; CONNECT and SOCKS5 CONNECT are opaque duplex tunnels.
No request/response payload, path, headers, or credentials enter the event log.
"""
from __future__ import annotations

import asyncio
from collections import deque
import concurrent.futures
import contextlib
import copy
import ipaddress
import os
import queue
import re
import socket
import struct
import threading
import time
from urllib.parse import urlsplit
import uuid

from .policy import Policy, normalize_host, validate_plan

# Microsoft-generated WinSock constants and documented byte order:
# https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/constant.IP_UNICAST_IF.html
# https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/constant.IPV6_UNICAST_IF.html
# https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
# https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options
IP_UNICAST_IF = IPV6_UNICAST_IF = 31
TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_blocking_dns_slots = threading.BoundedSemaphore(8)


class RelayError(Exception):
    def __init__(self, code, stage="protocol", status=502):
        self.code, self.stage, self.status = code, stage, status
        super().__init__(code)


def _local_address(value):
    address = ipaddress.ip_address(value.split("%", 1)[0])
    mapped = getattr(address, "ipv4_mapped", None)
    return address.is_loopback or address.is_unspecified or bool(mapped and mapped.is_loopback)


def _bind_interface(sock, interface_index):
    if interface_index is None:
        return
    if os.name != "nt":
        raise RelayError("interface_binding_requires_windows", "interface")
    if isinstance(interface_index, bool) or not isinstance(interface_index, int) or not 1 <= interface_index <= 0xFFFFFF:
        raise RelayError("invalid_interface_index", "interface")
    if sock.family == socket.AF_INET:
        level, option, packed = socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", interface_index)
    elif sock.family == socket.AF_INET6:
        level, option, packed = socket.IPPROTO_IPV6, IPV6_UNICAST_IF, struct.pack("=I", interface_index)
    else:
        raise RelayError("unsupported_interface_address_family", "interface")
    try:
        sock.setsockopt(level, option, packed)
        if struct.unpack("=I", sock.getsockopt(level, option, 4))[0] != interface_index:
            raise RelayError("interface_binding_not_confirmed", "interface")
    except OSError:
        raise RelayError("interface_binding_failed", "interface") from None


def _authority(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _address_packet(host, port):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise RelayError("socks_domain_too_long", "protocol", 400)
        return b"\x03" + bytes([len(encoded)]) + encoded + struct.pack("!H", port)
    return (b"\x01" if address.version == 4 else b"\x04") + address.packed + struct.pack("!H", port)


def _validated_target(target):
    target = dict(target)
    target.setdefault("id", "probe")
    return validate_plan({"targets": [target], "channels": [{"id": "probe", "default_target": target["id"]}]})["targets"][0]


def _blocking_resolve(host, port, timeout):
    """Bound the caller's DNS wait without changing the OS resolver path."""
    try:
        address = ipaddress.ip_address(host)
        family = socket.AF_INET if address.version == 4 else socket.AF_INET6
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (host, port))]
    except ValueError:
        pass
    if not _blocking_dns_slots.acquire(blocking=False):
        raise RelayError("dns_resolver_busy", "dns", 503)
    result = queue.Queue(maxsize=1)
    def resolve():
        try:
            result.put((True, socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
        except OSError:
            result.put((False, None))
        finally:
            _blocking_dns_slots.release()
    try:
        threading.Thread(target=resolve, daemon=True, name="proxy-dns-probe").start()
    except Exception:
        _blocking_dns_slots.release()
        raise RelayError("dns_resolver_unavailable", "dns") from None
    try:
        ok, addresses = result.get(timeout=timeout)
    except queue.Empty:
        raise RelayError("dns_timeout", "dns", 504) from None
    if not ok:
        raise RelayError("dns_failed", "dns")
    return addresses


def _check_addresses(addresses, port, forbidden_ports):
    if port in forbidden_ports and any(_local_address(item[4][0]) for item in addresses):
        raise RelayError("local_control_or_relay_loop_blocked", "loop_guard", 403)


def connect_target(target, host, port, timeout=10, forbidden_ports=()):
    """Return a connected TCP socket through a target, for explicit probes.

    Returned sockets carry no environment/system HTTP proxy configuration.
    HTTP upstreams use CONNECT; SOCKS5 upstreams use NOAUTH TCP CONNECT. The
    timeout bounds this call's work (a daemon DNS resolver may finish later).
    Caller owns/ closes the returned socket. No application request is sent.
    """
    target, host = _validated_target(target), normalize_host(host)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Invalid destination port")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 3600:
        raise ValueError("Invalid connection timeout")
    deadline, forbidden = time.monotonic() + timeout, set(forbidden_ports)
    if target["type"] == "block":
        raise RelayError("blocked_by_policy", "policy", 403)
    def left():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RelayError("connection_timeout", "connect", 504)
        return remaining
    if port in forbidden:
        _check_addresses(_blocking_resolve(host, port, left()), port, forbidden)
    peer_host, peer_port = (host, port) if target["type"] == "direct" else (target["host"], target["port"])
    addresses = _blocking_resolve(peer_host, peer_port, left())
    _check_addresses(addresses, peer_port, forbidden)
    sock = None
    try:
        last_error = None
        for family, kind, protocol, _, address in addresses:
            candidate = socket.socket(family, kind, protocol)
            try:
                if target["type"] == "direct":
                    _bind_interface(candidate, target.get("interface_index"))
                candidate.settimeout(left())
                candidate.connect(address)
                sock = candidate
                break
            except RelayError:
                candidate.close()
                raise
            except OSError as error:
                last_error = error
                candidate.close()
        if sock is None:
            raise RelayError("tcp_connection_failed", "tcp") from last_error
        def exact(length):
            data = bytearray()
            while len(data) < length:
                sock.settimeout(left())
                block = sock.recv(length - len(data))
                if not block:
                    raise RelayError("upstream_closed", "upstream")
                data.extend(block)
            return bytes(data)
        if target["type"] == "http":
            authority = _authority(host, port)
            sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                if len(header) >= 32768:
                    raise RelayError("upstream_headers_too_large", "upstream_http")
                header.extend(exact(1))
            fields = header.split(b"\r\n", 1)[0].split(b" ")
            if len(fields) < 2 or not fields[0].startswith(b"HTTP/1.") or not fields[1].isdigit() or not 200 <= int(fields[1]) < 300:
                raise RelayError("http_upstream_connect_rejected", "upstream_http")
        elif target["type"] == "socks5":
            sock.sendall(b"\x05\x01\x00")
            if exact(2) != b"\x05\x00":
                raise RelayError("socks_upstream_requires_unsupported_auth", "upstream_socks")
            sock.sendall(b"\x05\x01\x00" + _address_packet(host, port))
            reply = exact(4)
            if reply[:3] != b"\x05\x00\x00":
                raise RelayError("socks_upstream_connect_rejected", "upstream_socks")
            length = {1: 4, 4: 16}.get(reply[3])
            if reply[3] == 3:
                length = exact(1)[0]
            if length is None:
                raise RelayError("invalid_socks_upstream_reply", "upstream_socks")
            exact(length + 2)
        sock.settimeout(timeout)
        return sock
    except (TimeoutError, socket.timeout):
        if sock:
            sock.close()
        raise RelayError("connection_timeout", "connect", 504) from None
    except BaseException:
        if sock:
            sock.close()
        raise


class RelayManager:
    def __init__(self, deny_ports=()):
        if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in deny_ports):
            raise ValueError("Invalid forbidden control port")
        self._deny_ports = set(deny_ports)
        self._lock, self._event_lock = threading.RLock(), threading.Lock()
        self._events, self._sequence = deque(maxlen=2000), 0
        self._loop = self._thread = self._policy = None
        self._servers, self._tasks, self._writers, self._channel_info = [], set(), set(), []
        self._owned_ports, self._stopping = set(), False

    def _event(self, **event):
        with self._event_lock:
            self._sequence += 1
            self._events.append({"id": self._sequence, "time": time.time(), **event})

    def events(self, after_id=0, limit=200):
        with self._event_lock:
            return [dict(event) for event in self._events if event["id"] > after_id][:max(1, min(int(limit), 2000))]

    def status(self):
        with self._lock:
            return {"running": bool(self._thread and self._thread.is_alive() and self._servers and not self._stopping),
                    "plan_id": self._policy.plan["id"] if self._policy else None,
                    "channels": copy.deepcopy(self._channel_info),
                    "active_connections": len(self._tasks),
                    "limits": dict(self._policy.plan["limits"]) if self._policy else {},
                    "capabilities": {"http": True, "connect": True, "socks5_tcp": True,
                                     "socks5_udp": False, "tls_mitm": False, "loopback_only": True,
                                     "upstream_authentication": False, "windows_interface_binding": os.name == "nt"},
                    "direct_notice": "Direct opens TCP sockets without an application proxy; system TUN/WFP may still intercept. Interface binding affects TCP only; DNS still uses the OS resolver and the adapter is not independently verified as physical."}

    def start(self, plan):
        policy = Policy(plan)
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("Relay is already running; stop it before starting another plan")
            self._policy, self._stopping = policy, False
            ready = concurrent.futures.Future()
            def run():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._loop = loop
                try:
                    loop.run_until_complete(self._start_servers())
                    ready.set_result({item["id"]: item["actual_port"] for item in self._channel_info})
                    loop.run_forever()
                except BaseException as error:
                    if not ready.done():
                        ready.set_exception(error)
                finally:
                    loop.run_until_complete(self._shutdown())
                    loop.close()
            self._thread = threading.Thread(target=run, name="proxyworkbench-relay", daemon=True)
            self._thread.start()
        try:
            return ready.result(timeout=10)
        except BaseException:
            self.stop()
            raise

    async def _start_servers(self):
        self._servers, self._tasks, self._writers, self._channel_info = [], set(), set(), []
        for channel in self._policy.plan["channels"]:
            server = await asyncio.start_server(lambda reader, writer, channel=channel: self._accept(channel, reader, writer),
                                                "127.0.0.1", channel["listen_port"], start_serving=False,
                                                limit=self._policy.plan["limits"]["max_header_bytes"] + 1024)
            self._servers.append(server)
            port = server.sockets[0].getsockname()[1]
            self._channel_info.append({"id": channel["id"], "name": channel["name"], "listen_host": "127.0.0.1",
                                       "listen_port": port, "actual_port": port, "config_id": uuid.uuid4().hex,
                                       "proxy_url": f"http://127.0.0.1:{port}", "socks_url": f"socks5h://127.0.0.1:{port}",
                                       "active_connections": 0, "default_target": channel["default_target"]})
        self._owned_ports = {item["actual_port"] for item in self._channel_info}
        for target in self._policy.targets.values():
            if target["type"] in ("http", "socks5") and target["port"] in self._owned_ports | self._deny_ports:
                addresses = await self._resolve(target["host"], target["port"])
                _check_addresses(addresses, target["port"], self._owned_ports | self._deny_ports)
        for server in self._servers:
            await server.start_serving()

    def stop(self):
        with self._lock:
            thread, loop = self._thread, self._loop
            self._stopping = True
        if thread and thread.is_alive() and loop and not loop.is_closed():
            future = asyncio.run_coroutine_threadsafe(self._shutdown(), loop)
            timeout = self._policy.plan["limits"]["stop_timeout"] if self._policy else 3
            with contextlib.suppress(Exception):
                future.result(timeout=timeout + 1)
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=timeout + 1)
        with self._lock:
            if not thread or not thread.is_alive():
                self._servers, self._channel_info, self._owned_ports = [], [], set()
                self._thread = self._loop = None
        return self.status()

    async def _shutdown(self):
        for server in list(self._servers):
            server.close()
        for writer in list(self._writers):
            writer.close()
            if self._stopping:
                writer.transport.abort()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        # Python 3.13 Server.wait_closed() also waits for active connections.
        # Close/cancel those first; awaiting the server first deadlocks until
        # tunnels reach their normal idle timeout.
        for server in list(self._servers):
            await server.wait_closed()
        self._servers, self._channel_info, self._owned_ports = [], [], set()

    def _accept(self, channel, reader, writer):
        if self._stopping or len(self._tasks) >= self._policy.plan["limits"]["max_connections"]:
            writer.close()
            self._event(connection_id=uuid.uuid4().hex, channel_id=channel["id"], status="rejected", stage="accept", code="connection_limit", bytes_up=0, bytes_down=0)
            return
        task = asyncio.create_task(self._handle(channel, reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _resolve(self, host, port):
        try:
            return await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
                                          self._policy.plan["limits"]["connect_timeout"])
        except asyncio.TimeoutError:
            raise RelayError("dns_timeout", "dns", 504) from None
        except OSError:
            raise RelayError("dns_failed", "dns") from None

    async def _dial(self, target, host, port, *, forward_http=False):
        if target["type"] == "block":
            raise RelayError("blocked_by_policy", "policy", 403)
        forbidden = self._owned_ports | self._deny_ports
        if port in forbidden:
            _check_addresses(await self._resolve(host, port), port, forbidden)
        peer_host, peer_port = (host, port) if target["type"] == "direct" else (target["host"], target["port"])
        addresses = await self._resolve(peer_host, peer_port)
        _check_addresses(addresses, peer_port, forbidden)
        deadline = time.monotonic() + self._policy.plan["limits"]["connect_timeout"]
        for family, kind, protocol, _, address in addresses:
            sock = socket.socket(family, kind, protocol)
            sock.setblocking(False)
            try:
                if target["type"] == "direct":
                    _bind_interface(sock, target.get("interface_index"))
                await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock, address), max(0.001, deadline - time.monotonic()))
                reader, writer = await asyncio.open_connection(sock=sock, limit=self._policy.plan["limits"]["max_header_bytes"] + 1024)
                self._writers.add(writer)
                break
            except RelayError:
                sock.close()
                raise
            except (OSError, asyncio.TimeoutError):
                sock.close()
        else:
            raise RelayError("tcp_connection_failed", "tcp")
        try:
            if target["type"] == "http" and not forward_http:
                authority = _authority(host, port)
                writer.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
                await self._drain(writer)
                header = await self._headers(reader)
                parts = header.split(b"\r\n", 1)[0].split(b" ")
                if len(parts) < 2 or not parts[0].startswith(b"HTTP/1.") or not parts[1].isdigit() or not 200 <= int(parts[1]) < 300:
                    raise RelayError("http_upstream_connect_rejected", "upstream_http")
            elif target["type"] == "socks5":
                writer.write(b"\x05\x01\x00")
                await self._drain(writer)
                if await self._exact(reader, 2) != b"\x05\x00":
                    raise RelayError("socks_upstream_requires_unsupported_auth", "upstream_socks")
                writer.write(b"\x05\x01\x00" + _address_packet(host, port))
                await self._drain(writer)
                reply = await self._exact(reader, 4)
                if reply[:3] != b"\x05\x00\x00":
                    raise RelayError("socks_upstream_connect_rejected", "upstream_socks")
                length = {1: 4, 4: 16}.get(reply[3])
                if reply[3] == 3:
                    length = (await self._exact(reader, 1))[0]
                if length is None:
                    raise RelayError("invalid_socks_upstream_reply", "upstream_socks")
                await self._exact(reader, length + 2)
            return reader, writer
        except BaseException:
            self._writers.discard(writer)
            writer.close()
            raise

    async def _exact(self, reader, length):
        try:
            return await asyncio.wait_for(reader.readexactly(length), self._policy.plan["limits"]["header_timeout"])
        except asyncio.IncompleteReadError:
            raise RelayError("unexpected_eof", "protocol", 400) from None

    async def _headers(self, reader, prefix=b""):
        try:
            header = prefix + await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self._policy.plan["limits"]["header_timeout"])
        except (asyncio.LimitOverrunError, ValueError):
            raise RelayError("headers_too_large", "headers", 431) from None
        except asyncio.IncompleteReadError:
            raise RelayError("incomplete_headers", "headers", 400) from None
        if len(header) > self._policy.plan["limits"]["max_header_bytes"]:
            raise RelayError("headers_too_large", "headers", 431)
        return header

    async def _drain(self, writer):
        await asyncio.wait_for(writer.drain(), self._policy.plan["limits"]["idle_timeout"])

    @staticmethod
    def _parse_headers(header):
        lines = header[:-4].split(b"\r\n")
        fields = []
        for line in lines[1:]:
            if b":" not in line or line.startswith((b" ", b"\t")):
                raise RelayError("malformed_header", "headers", 400)
            name, value = line.split(b":", 1)
            if not TOKEN.fullmatch(name) or any(byte < 32 and byte != 9 or byte == 127 for byte in value):
                raise RelayError("malformed_header", "headers", 400)
            fields.append((name, value.strip(b" \t")))
        return lines[0], fields

    @staticmethod
    def _framing(fields):
        lengths = [value for name, value in fields if name.lower() == b"content-length"]
        encodings = [value.lower() for name, value in fields if name.lower() == b"transfer-encoding"]
        if len(lengths) > 1 or len(encodings) > 1 or (lengths and encodings):
            raise RelayError("ambiguous_message_framing", "headers", 400)
        if lengths:
            if not re.fullmatch(rb"[0-9]{1,20}", lengths[0]):
                raise RelayError("invalid_content_length", "headers", 400)
            return "length", int(lengths[0])
        if encodings:
            if encodings[0] != b"chunked":
                raise RelayError("unsupported_transfer_encoding", "headers", 501)
            return "chunked", None
        return None, None

    @staticmethod
    def _destination(authority, default_port=None):
        try:
            parsed = urlsplit("//" + authority)
            if parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment:
                raise ValueError()
            host = normalize_host(parsed.hostname)
            port = parsed.port if parsed.port is not None else default_port
            if not port or not 1 <= port <= 65535:
                raise ValueError()
            return host, port
        except (TypeError, ValueError, UnicodeError):
            raise RelayError("invalid_destination", "headers", 400) from None

    async def _copy_length(self, reader, writer, length, counters, direction):
        while length:
            block = await asyncio.wait_for(reader.read(min(65536, length)), self._policy.plan["limits"]["idle_timeout"])
            if not block:
                raise RelayError("truncated_message_body", "body", 400)
            writer.write(block)
            await self._drain(writer)
            counters[direction] += len(block)
            length -= len(block)

    async def _copy_chunked(self, reader, writer, counters, direction):
        trailer_bytes = 0
        while True:
            try:
                line = await asyncio.wait_for(reader.readuntil(b"\r\n"), self._policy.plan["limits"]["idle_timeout"])
            except (ValueError, asyncio.LimitOverrunError, asyncio.IncompleteReadError):
                raise RelayError("invalid_chunked_body", "body", 400) from None
            if len(line) > 4096 or not re.fullmatch(rb"[0-9A-Fa-f]{1,16}(?:;[^\r\n]*)?\r\n", line):
                raise RelayError("invalid_chunked_body", "body", 400)
            if any(byte < 32 and byte != 9 for byte in line[:-2]) or b"\x7f" in line:
                raise RelayError("invalid_chunk_extension", "body", 400)
            length = int(line.split(b";", 1)[0].strip(), 16)
            writer.write(line)
            counters[direction] += len(line)
            if length:
                await self._copy_length(reader, writer, length, counters, direction)
                ending = await self._exact(reader, 2)
                if ending != b"\r\n":
                    raise RelayError("invalid_chunked_body", "body", 400)
                writer.write(ending)
                counters[direction] += 2
                await self._drain(writer)
                continue
            while True:
                trailer = await asyncio.wait_for(reader.readuntil(b"\r\n"), self._policy.plan["limits"]["idle_timeout"])
                trailer_bytes += len(trailer)
                if trailer_bytes > self._policy.plan["limits"]["max_header_bytes"]:
                    raise RelayError("trailers_too_large", "body", 431)
                if trailer != b"\r\n":
                    if b":" not in trailer or not TOKEN.fullmatch(trailer.split(b":", 1)[0]) or trailer.startswith((b" ", b"\t")):
                        raise RelayError("invalid_chunked_trailer", "body", 400)
                    if trailer.split(b":", 1)[0].lower() in (b"host", b"content-length", b"transfer-encoding", b"connection", b"proxy-authorization"):
                        raise RelayError("invalid_chunked_trailer", "body", 400)
                    if any(byte < 32 and byte != 9 or byte == 127 for byte in trailer[:-2]):
                        raise RelayError("invalid_chunked_trailer", "body", 400)
                writer.write(trailer)
                counters[direction] += len(trailer)
                await self._drain(writer)
                if trailer == b"\r\n":
                    return

    async def _bridge(self, left_reader, left_writer, right_reader, right_writer, counters):
        activity = [time.monotonic()]
        async def pump(reader, writer, direction):
            while True:
                block = await reader.read(65536)
                if not block:
                    if writer.can_write_eof():
                        with contextlib.suppress(OSError):
                            writer.write_eof()
                            await writer.drain()
                    return
                writer.write(block)
                await writer.drain()
                counters[direction] += len(block)
                activity[0] = time.monotonic()
        tasks = {asyncio.create_task(pump(left_reader, right_writer, "bytes_up")),
                 asyncio.create_task(pump(right_reader, left_writer, "bytes_down"))}
        try:
            while tasks:
                timeout = self._policy.plan["limits"]["idle_timeout"] - (time.monotonic() - activity[0])
                done, _ = await asyncio.wait(tasks, timeout=max(0.01, timeout), return_when=asyncio.FIRST_COMPLETED)
                if not done and time.monotonic() - activity[0] >= self._policy.plan["limits"]["idle_timeout"]:
                    raise RelayError("tunnel_idle_timeout", "tunnel", 504)
                for task in done:
                    tasks.remove(task)
                    task.result()
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def _handle(self, channel, reader, writer):
        self._writers.add(writer)
        counters = {"bytes_up": 0, "bytes_down": 0}
        event = {"connection_id": uuid.uuid4().hex, "channel_id": channel["id"], "protocol": "unknown", "host": None, "port": None,
                 "dial_host": None, "dns_source": None, "target_id": None, "rule_id": None,
                 "stage": "protocol", "status": "error"}
        upstream_writer, established, socks_greeted = None, False, False
        info = next((item for item in self._channel_info if item["id"] == channel["id"]), None)
        if info:
            info["active_connections"] += 1
        def connected():
            # Emitted while the connection remains open. This proves only the
            # TCP path / proxy handshake, never the destination application.
            self._event(**{**event, "status": "connected", "stage": "established"}, **counters)
        try:
            first = await self._exact(reader, 1)
            if first == b"\x05":
                event["protocol"] = "socks5"
                methods = await self._exact(reader, (await self._exact(reader, 1))[0])
                if not methods or 0 not in methods:
                    writer.write(b"\x05\xff")
                    await self._drain(writer)
                    raise RelayError("socks_authentication_unsupported", "protocol", 407)
                writer.write(b"\x05\x00")
                await self._drain(writer)
                socks_greeted = True
                request = await self._exact(reader, 4)
                if request[:3] != b"\x05\x01\x00":
                    raise RelayError("socks_bind_udp_unsupported", "protocol", 501)
                atyp = request[3]
                if atyp in (1, 4):
                    host = socket.inet_ntop(socket.AF_INET if atyp == 1 else socket.AF_INET6, await self._exact(reader, 4 if atyp == 1 else 16))
                elif atyp == 3:
                    host = (await self._exact(reader, (await self._exact(reader, 1))[0])).decode("ascii")
                else:
                    raise RelayError("socks_address_type_unsupported", "protocol", 400)
                port = struct.unpack("!H", await self._exact(reader, 2))[0]
                decision = self._policy.route(channel["id"], host, port)
                event.update({key: decision[key] for key in ("host", "dial_host", "dns_source", "port", "target_id", "rule_id")})
                event["stage"] = "connect"
                upstream_reader, upstream_writer = await self._dial(decision["target"], decision["dial_host"], port)
                writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                await self._drain(writer)
                established, event["stage"] = True, "tunnel"
                connected()
                await self._bridge(reader, writer, upstream_reader, upstream_writer, counters)
            else:
                event["protocol"] = "http"
                header = await self._headers(reader, first)
                start, fields = self._parse_headers(header)
                parts = start.split(b" ")
                if (len(parts) != 3 or not TOKEN.fullmatch(parts[0]) or parts[2] not in (b"HTTP/1.0", b"HTTP/1.1")
                        or any(byte < 33 or byte > 126 for byte in parts[1])):
                    raise RelayError("invalid_request_line", "headers", 400)
                method, raw_url = parts[0].decode("ascii"), parts[1].decode("ascii")
                framing, length = self._framing(fields)
                if method == "CONNECT":
                    host, port = self._destination(raw_url)
                    if framing is not None and length != 0:
                        raise RelayError("connect_body_unsupported", "headers", 400)
                    decision = self._policy.route(channel["id"], host, port)
                    event.update({key: decision[key] for key in ("host", "dial_host", "dns_source", "port", "target_id", "rule_id")})
                    event["protocol"], event["stage"] = "connect", "connect"
                    upstream_reader, upstream_writer = await self._dial(decision["target"], decision["dial_host"], port)
                    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await self._drain(writer)
                    established, event["stage"] = True, "tunnel"
                    connected()
                    await self._bridge(reader, writer, upstream_reader, upstream_writer, counters)
                else:
                    parsed = urlsplit(raw_url)
                    if parsed.scheme != "http" or parsed.username is not None or parsed.password is not None or parsed.fragment:
                        raise RelayError("http_absolute_url_required", "headers", 400)
                    host, port = self._destination(parsed.netloc, 80)
                    hosts = [value for name, value in fields if name.lower() == b"host"]
                    if len(hosts) != 1 or self._destination(hosts[0].decode("ascii"), 80) != (host, port):
                        raise RelayError("ambiguous_host_header", "headers", 400)
                    if any(name.lower() == b"upgrade" for name, _ in fields):
                        raise RelayError("http_upgrade_requires_connect", "headers", 501)
                    expects = [value.lower() for name, value in fields if name.lower() == b"expect"]
                    if expects and expects != [b"100-continue"]:
                        raise RelayError("unsupported_expectation", "headers", 417)
                    connections = {token.strip().lower() for name, value in fields if name.lower() == b"connection" for token in value.split(b",")}
                    if connections & {b"host", b"content-length", b"transfer-encoding"}:
                        raise RelayError("ambiguous_hop_headers", "headers", 400)
                    decision = self._policy.route(channel["id"], host, port)
                    event.update({key: decision[key] for key in ("host", "dial_host", "dns_source", "port", "target_id", "rule_id")})
                    event["stage"] = "connect"
                    target = decision["target"]
                    forward_http = target["type"] == "http" and decision["dns_source"] != "plan_override"
                    upstream_reader, upstream_writer = await self._dial(target, decision["dial_host"], port, forward_http=forward_http)
                    connected()
                    path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
                    outbound = ("http://" + _authority(host, port) + path) if forward_http else path
                    remove = connections | {b"connection", b"proxy-connection", b"proxy-authorization", b"keep-alive", b"te", b"expect"}
                    forwarded = [(name, value) for name, value in fields if name.lower() not in remove]
                    request = method.encode("ascii") + b" " + outbound.encode("ascii") + b" HTTP/1.1\r\n"
                    request += b"".join(name + b": " + value + b"\r\n" for name, value in forwarded) + b"Connection: close\r\n\r\n"
                    upstream_writer.write(request)
                    await self._drain(upstream_writer)
                    counters["bytes_up"] += len(request)
                    if expects:
                        writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                        await self._drain(writer)
                    event["stage"] = "request_body"
                    if framing == "length":
                        await self._copy_length(reader, upstream_writer, length, counters, "bytes_up")
                    elif framing == "chunked":
                        await self._copy_chunked(reader, upstream_writer, counters, "bytes_up")
                    event["stage"] = "response"
                    for _ in range(9):
                        response = await self._headers(upstream_reader)
                        response_start, response_fields = self._parse_headers(response)
                        response_parts = response_start.split(b" ", 2)
                        if not re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2}(?: [^\x00-\x1f\x7f]*)?", response_start):
                            raise RelayError("invalid_upstream_response", "response")
                        response_status = int(response_parts[1])
                        if response_status == 101:
                            raise RelayError("upstream_upgrade_unsupported", "response")
                        response_framing, response_length = self._framing(response_fields)
                        if response_status >= 200:
                            response_connections = {token.strip().lower() for name, value in response_fields
                                                    if name.lower() == b"connection" for token in value.split(b",")}
                            if response_connections & {b"content-length", b"transfer-encoding"}:
                                raise RelayError("ambiguous_upstream_hop_headers", "response")
                            remove_response = response_connections | {b"connection", b"proxy-connection", b"keep-alive"}
                            response = response_start + b"\r\n" + b"".join(
                                name + b": " + value + b"\r\n" for name, value in response_fields
                                if name.lower() not in remove_response) + b"Connection: close\r\n\r\n"
                        writer.write(response)
                        await self._drain(writer)
                        counters["bytes_down"] += len(response)
                        if response_status >= 200:
                            established = True
                            break
                    else:
                        raise RelayError("too_many_interim_responses", "response")
                    event["http_status"] = response_status
                    if method == "HEAD" or response_status in (204, 304):
                        pass
                    elif response_framing == "length":
                        await self._copy_length(upstream_reader, writer, response_length, counters, "bytes_down")
                    elif response_framing == "chunked":
                        await self._copy_chunked(upstream_reader, writer, counters, "bytes_down")
                    else:
                        while block := await asyncio.wait_for(upstream_reader.read(65536), self._policy.plan["limits"]["idle_timeout"]):
                            writer.write(block)
                            await self._drain(writer)
                            counters["bytes_down"] += len(block)
            event.update(status="completed", stage="complete")
        except asyncio.CancelledError:
            event.update(status="stopped", stage="stop", code="relay_stopped")
        except (RelayError, OSError, asyncio.TimeoutError, ValueError, UnicodeError, asyncio.IncompleteReadError, RuntimeError) as error:
            if isinstance(error, RelayError):
                failure = error
            elif isinstance(error, (asyncio.TimeoutError, TimeoutError)):
                failure = RelayError("operation_timeout", event["stage"], 504)
            elif isinstance(error, (ValueError, UnicodeError, asyncio.IncompleteReadError)):
                failure = RelayError("invalid_protocol_data", event["stage"], 400)
            else:
                failure = RelayError("connection_closed_or_failed", event["stage"], 502)
            event.update(status="blocked" if failure.status == 403 else "error", stage=failure.stage, code=failure.code)
            if not established:
                with contextlib.suppress(Exception):
                    if event["protocol"] == "socks5" and socks_greeted:
                        writer.write(b"\x05" + bytes([7 if failure.status == 501 else 2 if failure.status == 403 else 1]) + b"\x00\x01\x00\x00\x00\x00\x00\x00")
                    elif event["protocol"] != "socks5":
                        reason = {400: "Bad Request", 403: "Forbidden", 407: "Authentication Required", 417: "Expectation Failed", 431: "Request Header Fields Too Large", 501: "Not Implemented", 504: "Gateway Timeout"}.get(failure.status, "Bad Gateway")
                        writer.write(f"HTTP/1.1 {failure.status} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode("ascii"))
                    await self._drain(writer)
        finally:
            self._event(**event, **counters)
            if info:
                info["active_connections"] -= 1
            for connection in (upstream_writer, writer):
                if connection:
                    self._writers.discard(connection)
                    connection.close()
                    if self._stopping:
                        connection.transport.abort()
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(connection.wait_closed(), 0.1 if self._stopping else 1)
