# N2 - GHOST IN THE WIRE - participant evidence portal
# Tiny, dependency-free. Copies ONLY portal/ + evidence/; organizer/ is excluded.
FROM python:3.12-slim AS portal

# No package installs, no network needed at build time beyond the base image.
WORKDIR /app

# Copy the portal application and templates/static
COPY portal/app.py ./app.py
COPY portal/templates/ ./templates/
COPY portal/static/ ./static/

# Copy the participant evidence (read-only intent; the compose file mounts it
# read-only at the same path).
COPY evidence/ ./evidence/

# Run as a non-root user
RUN useradd --create-home --uid 10001 n2portal \
 && chown -R n2portal:n2portal /app
USER n2portal

ENV HOST=0.0.0.0 \
    PORT=8080 \
    EVIDENCE_DIR=/app/evidence \
    PYTHONUNBUFFERED=1

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8080/', timeout=3); sys.exit(0)" || exit 1

CMD ["python", "/app/app.py"]
