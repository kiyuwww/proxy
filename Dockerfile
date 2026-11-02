# syntax=docker/dockerfile:1

# 1) Fetch pinned browser bundles (Scramjet, libcurl transport, bare-mux).
FROM node:22-alpine AS assets
WORKDIR /w
COPY scripts/fetch-assets.sh .
RUN sh fetch-assets.sh /w/out

# 2) Build a fully static C++ binary (musl) - no runtime dependencies.
FROM alpine:3.20 AS build
RUN apk add --no-cache build-base cmake boost-dev zlib-dev zlib-static
WORKDIR /src
COPY CMakeLists.txt ./
COPY src ./src
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSCRAMJET_STATIC=ON \
 && cmake --build build -j"$(nproc)" \
 && strip build/scramjet_server

# 3) Minimal runtime image.
FROM alpine:3.20
RUN adduser -D -H -u 10001 app
WORKDIR /app
COPY --from=build /src/build/scramjet_server ./scramjet_server
COPY public ./public
COPY --from=assets /w/out ./static
ENV PORT=8080 PUBLIC_DIR=public STATIC_DIR=static
EXPOSE 8080
USER app
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:${PORT}/app-config.js >/dev/null || exit 1
CMD ["./scramjet_server"]
