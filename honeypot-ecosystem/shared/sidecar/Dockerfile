# Holds the HMAC signing key. Nothing an attacker can reach can produce a
# valid signature, because nothing an attacker can reach runs this.
FROM python:3.11-slim

WORKDIR /app
COPY shared/sidecar/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/sidecar/ /app/

RUN useradd --system --uid 10023 --no-create-home sidecar \
    && mkdir -p /var/lib/sidecar/pending \
    && chown -R sidecar:sidecar /var/lib/sidecar

USER sidecar
ENV PYTHONUNBUFFERED=1
CMD ["python", "shipper.py"]
