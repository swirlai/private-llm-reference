# Build context is the REPO ROOT, not this directory: the image needs common/
# alongside services/idp/ so `common.jwt_tools` imports the same way it does
# under `make dev`.
#   docker build -f services/idp/Dockerfile .
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY services/idp/requirements.txt /app/services/idp/requirements.txt
RUN pip install --no-cache-dir -r /app/services/idp/requirements.txt

COPY common/ /app/common/
COPY services/idp/app.py /app/services/idp/app.py

# Non-root: nothing here needs to write to the filesystem, and the signing key
# only ever exists in memory.
RUN useradd --create-home --uid 10001 idp && chown -R idp:idp /app
USER idp

EXPOSE 8081

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8081/healthz').read()"

CMD ["uvicorn", "services.idp.app:app", "--host", "0.0.0.0", "--port", "8081"]
