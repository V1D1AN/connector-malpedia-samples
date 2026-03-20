FROM python:3.11-slim

# ── System deps ──────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# ── App ──────────────────────────────────────────────────────────────────
WORKDIR /opt/connector-malpedia-samples

COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

ENTRYPOINT ["python", "main.py"]
