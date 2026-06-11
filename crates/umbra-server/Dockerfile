FROM rust:1.85 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p umbra-server

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/umbra-server /usr/local/bin/umbra-server
EXPOSE 8080
ENTRYPOINT ["umbra-server"]
CMD ["serve"]
