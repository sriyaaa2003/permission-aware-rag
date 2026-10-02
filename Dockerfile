FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PR_DB_PATH=/data/permrag.db
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 app \
    && mkdir /data && chown app /data
USER app
VOLUME /data
EXPOSE 8000
CMD ["permrag", "serve", "--host", "0.0.0.0", "--port", "8000"]
