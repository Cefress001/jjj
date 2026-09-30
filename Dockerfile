# Full Offensive Emulator image: app + all automatic web assessment tools.
#
#   docker build -t offensive-emulator .
#   docker run --rm -p 8000:8000 offensive-emulator
#
# The scanner binaries are copied from their official images. They run as
# internal pipeline stages; users still submit one target and receive one report.

FROM projectdiscovery/httpx:latest AS httpx
FROM projectdiscovery/katana:latest AS katana
FROM projectdiscovery/nuclei:latest AS nuclei
# Bake a template snapshot into the image so the first scan does not depend on
# a runtime template download. Phase 8 will add explicit signed-version pinning.
RUN nuclei -update-templates -update-template-dir /opt/nuclei-templates

FROM ghcr.io/zaproxy/zaproxy:stable

USER root
WORKDIR /app

# ProjectDiscovery publishes static Go binaries at this path in the official
# images. ZAP and its packaged baseline script are already present under /zap.
COPY --from=httpx /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=katana /usr/local/bin/katana /usr/local/bin/katana
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=nuclei --chown=zap:zap /opt/nuclei-templates /home/zap/nuclei-templates

COPY --chown=zap:zap run.py requirements.txt ./
COPY --chown=zap:zap offensive_emulator ./offensive_emulator

# Install the core HTTP dependency and a pinned Playwright/Chromium pair.
# A shared browser path keeps Chromium readable after dropping to user `zap`.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN python3 -m pip install --break-system-packages --no-cache-dir \
      aiohttp playwright==1.63.0 && \
    python3 -m playwright install --with-deps chromium && \
    chmod -R a+rX /ms-playwright

ENV PYTHONUNBUFFERED=1 \
    ZAP_BASELINE_COMMAND="/zap/zap-baseline.py -m 2" \
    HTTPX_COMMAND="/usr/local/bin/httpx" \
    KATANA_COMMAND="/usr/local/bin/katana" \
    NUCLEI_COMMAND="/usr/local/bin/nuclei" \
    NUCLEI_TEMPLATES_DIR="/home/zap/nuclei-templates"

USER zap
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status==200 else 1)"

ENTRYPOINT []
CMD ["python3", "/app/run.py", "--port", "8000", "--no-open"]
