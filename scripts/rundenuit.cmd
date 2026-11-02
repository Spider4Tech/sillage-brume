@echo off
rem Campagne de nuit SILLAGE sous Windows : voir scripts/rundenuit.ps1 et docs/CAMPAGNE_24H.md
rem   scripts/rundenuit.cmd [heures] [-Neuf]  ^|  scripts/rundenuit.cmd -Statut  ^|  scripts/rundenuit.cmd -Arreter
rem Passe outre la politique d'exécution de Windows pour ce seul script, sans la modifier.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0rundenuit.ps1" %*
set RC=%ERRORLEVEL%
pause
exit /b %RC%
