FROM rust:1.97-bookworm AS backend-build
WORKDIR /app
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_REGISTRIES_CRATES_IO_INDEX=sparse+https://rsproxy.cn/index/ \
    CARGO_HTTP_MULTIPLEXING=false
COPY .cargo/config.toml .cargo/config.toml
COPY server/Cargo.toml server/Cargo.lock ./
COPY server/src ./src
COPY server/migrations ./migrations
RUN cargo build --release

FROM node:22-bookworm-slim AS frontend-build
WORKDIR /app
COPY web/package*.json ./
RUN npm ci
COPY web ./
RUN npm run build

FROM debian:bookworm-slim
COPY --from=backend-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN useradd --system --uid 10001 --create-home llmroute
WORKDIR /app
COPY --from=backend-build /app/target/release/llmroute-server /usr/local/bin/llmroute-server
COPY --from=backend-build /app/migrations /app/migrations
COPY --from=frontend-build /app/dist /app/web/dist
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh && mkdir -p /app/data && chown -R llmroute:llmroute /app
USER llmroute
ENV PORT=7900 DATABASE_URL=sqlite:///app/data/llmroute.db?mode=rwc WEB_DIST=/app/web/dist
EXPOSE 7900
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
