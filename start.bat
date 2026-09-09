@echo off
title GovSite Checker
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0server.ps1"
pause