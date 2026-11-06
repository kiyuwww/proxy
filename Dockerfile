# syntax=docker/dockerfile:1

# 1) Fetch pinned browser bundles (Scramjet, libcurl transport, bare-mux).
FROM node:22-alpine AS assets
WORKDIR /w
COPY scripts/fetch-assets.sh .
RUN sh fetch-assets.sh /w/out

# 2) Build the C++ server (dynamic: links libpq and OpenSSL from the runtime image).
FROM alpine:3.20 AS build
RUN apk add --no-cache build-base cmake boost-dev zlib-dev postgresql-dev openssl-dev
WORKDIR /src
COPY CMakeLists.txt ./
COPY src ./src
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j"$(nproc)" \
 && strip build/scramjet_server

# 3) Small runtime image.
FROM alpine:3.20
RUN apk add --no-cache libstdc++ libgcc libpq libssl3 libcrypto3 ca-certificates \
 && adduser -D -H -u 10001 app
WORKDIR /app
COPY --from=build /src/build/scramjet_server ./scramjet_server
COPY public ./public
COPY --from=assets /w/out ./static
ENV PORT=8080 PUBLIC_DIR=public STATIC_DIR=static
EXPOSE 8080
# Compress once at build time: the server then starts instantly instead of spending
# seconds of a 0.1 vCPU compressing megabytes of JS/WASM on every cold start.
RUN find public static -type f \( -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.json' \
        -o -name '*.wasm' -o -name '*.svg' -o -name '*.txt' \) -exec gzip -9 -k -f {} + \
 && chown -R app:app /app
USER app
HEALTHCHECK --interval=60s --timeout=3s CMD wget -qO- http://127.0.0.1:${PORT}/healthz >/dev/null || exit 1
CMD ["./scramjet_server"]
