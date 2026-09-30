# Offensive Emulator — one-image app (UI + API + built-in demo target)
#
#   docker build -t offensive-emulator .
#   docker run --rm -p 8000:8000 offensive-emulator
#
# Zero Python dependencies at runtime. Pass --build-arg WITH_AIOHTTP=1 to
# enable the real HTTP attack engines (falls back to simulation otherwise).

FROM python:3.11-slim AS base
WORKDIR /app
COPY run.py requirements.txt ./
COPY offensive_emulator ./offensive_emulator

ARG WITH_AIOHTTP=0
RUN if [ "$WITH_AIOHTTP" = "1" ]; then pip install --no-cache-dir aiohttp; fi

ENV PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status==200 else 1)"

CMD ["python3", "run.py", "--port", "8000", "--no-open"]
