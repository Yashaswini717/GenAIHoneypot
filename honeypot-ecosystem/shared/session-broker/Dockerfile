# Owns the Docker socket, and is therefore never exposed to the internet.
# Splitting this from the SSH proxy is the point: the process attackers can
# reach must not be the process that can create containers.
FROM python:3.11-slim

WORKDIR /app
COPY shared/session-broker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/session-broker/ /app/

ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["uvicorn", "broker:app", "--host", "0.0.0.0", "--port", "8080"]
