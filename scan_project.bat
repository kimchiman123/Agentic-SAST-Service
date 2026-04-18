@echo off
chcp 65001 >nul
title Agentic-SAST-Guardian 자동 분석기

:: 파이썬 가상환경 또는 프로젝트 디렉토리 경로 (현재 위치 기준)
set "GUARDIAN_DIR=%~dp0"

echo ==============================================================
echo        🛡️ Agentic-SAST-Guardian 원클릭 분석 도구 🛡️
echo ==============================================================
echo.

:: 드래그 앤 드롭으로 전달받은 타겟 폴더 확인
if "%~1"=="" (
    echo [!] 오류: 분석할 타겟 경로가 지정되지 않았습니다.
    echo [💡 팁] 분석할 소스코드 폴더를 마우스로 끌어서 이 bat 파일 위에 놓아주세요.
    echo.
    echo 테스트 용도로 vuln-test-app 폴더를 분석할까요? (Y/N)
    set /p CHOICE="선택: "
    if /I "%CHOICE%"=="Y" (
        set "TARGET_DIR=%GUARDIAN_DIR%vuln-test-app"
    ) else (
        pause
        exit /b 1
    )
) else (
    set "TARGET_DIR=%~1"
)

echo [*] 분석 대상: %TARGET_DIR%
echo.
echo [*] 엔진을 가동합니다... (최대 수 분이 소요될 수 있습니다)
echo.

:: 실제 main.py 실행 (타겟 폴더 전달)
pushd "%GUARDIAN_DIR%"
python main.py --target "%TARGET_DIR%"
popd

echo.
echo [✅] 분석이 모두 완료되었습니다!
echo 생성된 리포트(sast_report.html)를 확인해주세요.
pause
