FROM node:24-bookworm-slim AS web
WORKDIR /build
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

FROM eclipse-temurin:21-jdk AS java

FROM python:3.12-slim-bookworm AS runtime
COPY --from=java /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk \
    PATH=/opt/java/openjdk/bin:$PATH \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    GHIDRAMA_DATA_DIR=/var/lib/ghidrama \
    GHIDRAMA_FRONTEND_DIR=/app/frontend/dist \
    PYTHONUNBUFFERED=1 \
    LANGSMITH_TRACING=false \
    LANGCHAIN_TRACING_V2=false
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 libfreetype6 fontconfig \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 analyst \
    && mkdir -p /var/lib/ghidrama /opt/ghidra \
    && chown analyst:analyst /var/lib/ghidrama
COPY requirements.lock pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.lock
COPY backend/ ./backend/
RUN pip install --no-deps -e .
COPY --from=web /build/dist /app/frontend/dist
USER analyst
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "ghidrama.main:app", "--host", "0.0.0.0", "--port", "8000"]
