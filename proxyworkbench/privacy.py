"""Diagnostics retain topology and outcomes while removing credential material."""
import re
from urllib.parse import urlsplit, urlunsplit

SENSITIVE = re.compile(r'(password|passwd|passphrase|secret|token|authorization|subscription|uuid|private.?key|cookie|credential|raw.?config|command.?line|api.?key|username)', re.I)
UUID = re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I)
NODE = re.compile(r'\b(vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic|wireguard|snell)://[^\s"<>]+', re.I)
URL = re.compile(r'(?:https?|socks4a?|socks5h?)://[^\s"<>]+', re.I)
_PUBLIC_PATHS = {'', '/', '/dns-query', '/generate_204', '/favicon.ico', '/v1/responses'}


def redact(value):
    if isinstance(value, dict):
        return {str(key): ('<已隐藏>' if SENSITIVE.search(str(key)) else redact(item)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if not isinstance(value, str):
        return value
    if re.search(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----', value):
        return '<已隐藏的私钥>'
    value = NODE.sub('<已隐藏的节点链接>', value)

    def clean(match):
        try:
            url = urlsplit(match.group())
            authority = url.netloc.rsplit('@', 1)[-1]
            path = url.path if url.path in _PUBLIC_PATHS else '/<已隐藏路径>'
            return urlunsplit((url.scheme, authority, path, '<已隐藏查询参数>' if url.query else '', ''))
        except ValueError:
            return '<已隐藏的 URL>'

    value = URL.sub(clean, value)
    value = UUID.sub('<已隐藏的 UUID>', value)
    value = re.sub(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b', '<已隐藏的令牌>', value)
    value = re.sub(r'(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_.=-]+', '<已隐藏的认证信息>', value)
    value = re.sub(r'[^\s;=/@]+:[^\s;/@]+@(?=[\w\[.:-])', '<已隐藏凭据>@', value)
    value = re.sub(r'''(?ix)\b(password|passwd|passphrase|secret|token|api[_-]?key|authorization|cookie)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)''', r'\1=<已隐藏>', value)
    return value
