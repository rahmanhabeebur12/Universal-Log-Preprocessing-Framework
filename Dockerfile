FROM node:22-alpine AS frontend-builder
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ULPF_DB_PATH=/data/ulpf.db
WORKDIR /opt/ulpf
COPY requirements-runtime.txt ./
RUN pip install --no-cache-dir -r requirements-runtime.txt \
    && useradd --create-home --uid 10001 ulpf \
    && mkdir -p /data \
    && chown ulpf:ulpf /data
COPY app/ ./app/
COPY --from=frontend-builder /build/frontend/dist/ ./frontend/dist/
USER ulpf
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
