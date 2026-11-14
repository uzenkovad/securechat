# Збірка з кореня репозиторію (потрібна спільна бібліотека cryptolib):
#   docker build -f server/Dockerfile -t securechat-server .
#   docker run --rm -p 8000:8000 securechat-server
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Спільна бібліотека окремо від сервера — шар кешується, поки вона не змінилась
COPY cryptolib/ ./cryptolib/
RUN pip install ./cryptolib

COPY server/ ./server/
RUN pip install ./server

# Не запускаємо від root
RUN useradd --create-home appuser
USER appuser

ENV HOST=0.0.0.0 PORT=8000
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"

CMD ["python", "-m", "securechat_server"]
