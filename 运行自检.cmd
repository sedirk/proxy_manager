@echo off
cd /d "%~dp0"
python -X utf8 -m unittest discover -s tests -v
pause
