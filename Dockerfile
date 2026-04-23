# Python 3.11 Slim 버전 사용 (가볍고 최신 안정 버전)
FROM python:3.11-slim

# 환경 변수 설정
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# 작업 디렉토리 설정
WORKDIR /app

# 필수 OS 패키지 설치
# - ripgrep: core/mcp_tools.py 등에서 빠른 검색을 위해 필요
# - wkhtmltopdf, fonts-nanum: PDF 리포트 파일 생성을 위해 필요
# - build-essential: 일부 Python 패키지(C확장) 빌드용
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ripgrep \
    wkhtmltopdf \
    fonts-nanum \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# requirements.txt 복사 및 의존성 설치
COPY requirements.txt .

# pip 업그레이드 및 패키지 설치 (Semgrep 포함)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir semgrep

# 전체 프로젝트 소스코드 복사
COPY . .

# ENTRYPOINT 설정
# 컨테이너 실행 시 기본적으로 main.py를 실행하며, 
# 'docker run -v /내/프로젝트:/target ... --target /target' 의 형태로 사용됨
ENTRYPOINT ["python", "main.py"]
