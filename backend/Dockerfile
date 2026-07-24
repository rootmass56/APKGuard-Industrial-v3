FROM python:3.11-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --create-home --uid 10001 apkguard
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data/quarantine && chmod +x /app/entrypoint-api.sh && chown -R apkguard:apkguard /app
USER apkguard
EXPOSE 8000
CMD ["/app/entrypoint-api.sh"]
