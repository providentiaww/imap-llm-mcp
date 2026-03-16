FROM python:3.11-slim

LABEL org.opencontainers.image.maintainer="ryan.quick@providentiaworldwide.com"
LABEL org.opencontainers.image.vendor="Providentia Worldwide"
LABEL org.opencontainers.image.description="Risa — IMAP spam triage cron job"

RUN addgroup --gid 1000 risa && \
    adduser --disabled-password --uid 1000 --gid 1000 risa

WORKDIR /app
COPY cron/risa-triage.py .

RUN mkdir -p /config /tmp && chown -R risa:risa /app /tmp

USER risa

ENTRYPOINT ["python3", "/app/risa-triage.py"]
