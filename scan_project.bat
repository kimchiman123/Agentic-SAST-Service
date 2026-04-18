@echo off
:: 인코딩을 UTF-8(65001)로 설정
chcp 65001 >nul

title Agentic-SAST-Guardian 분석기

:: 프로젝트 디렉토리 경로 (현재 위치)
set "GUARDIAN_DIR=%~dp0"

echo ==============================================================
echo        🛡️ Agentic-SAST-Guardian 원클릭 분석 도구 🛡️
echo ==============================================================
echo.

:: 1. 타겟 경로 확인 (드래그 앤 드롭 지원)
set "TARGET_DIR=%~1"

if "%TARGET_DIR%"=="" (
    echo [!] 오류: 분석할 폴더가 지정되지 않았습니다.
    echo [💡] 팁: 분석할 폴더를 이 bat 파일 위로 끌어다 놓으세요.
    echo.
    echo 테스트용 vuln-test-app 폴더를 분석할까요? (Y/N)
    set /p "USER_CHOICE=선택: "
) else (
    goto :RUN_SCAN
)

:: 대문자로 변환하여 비교
if /I "%USER_CHOICE%"=="Y" (
    set "TARGET_DIR=%GUARDIAN_DIR%vuln-test-app"
    goto :RUN_SCAN
) else (
    echo 분석을 취소했습니다.
    pause
    exit /b 0
)

:RUN_SCAN
echo.
echo [*] 분석 대상: %TARGET_DIR%
echo [*] 분석을 시작합니다... (잠시만 기다려주세요)
echo.

:: 2. main.py 실행
pushd "%GUARDIAN_DIR%"
:: python 명령어로 실행 (환경에 따라 py 사용 가능)
python main.py --target "%TARGET_DIR%"
if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] 분석 도중 오류가 발생했습니다. 파이썬 설치 및 라이브러리를 확인해주세요.
)
popd

echo.
echo [✅] 분석 완료!
echo 생성된 리포트(sast_report.html)를 확인해주세요.
echo.
pause
