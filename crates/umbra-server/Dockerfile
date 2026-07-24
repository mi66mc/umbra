FROM rust:1.88-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --locked --release -p umbra-server

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/umbra-server /usr/local/bin/umbra-server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["umbra-server"]
CMD ["serve"]
