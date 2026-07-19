@echo off
chcp 65001 >nul
set "GUARDIAN_DIR=%~dp0"
pushd "%GUARDIAN_DIR%"
python -m streamlit run ui/app.py --server.address=127.0.0.1 --server.enableXsrfProtection=true --server.enableCORS=true --browser.gatherUsageStats=false
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%
