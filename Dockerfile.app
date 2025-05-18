# syntax=docker/dockerfile:1.4

### Stage 1: compile BPF object ###
FROM debian:bookworm-slim AS bpf-builder

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      clang llvm libbpf-dev libelf-dev linux-libc-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY bpf/hook_funcs.bpf.c .

# include multi-arch asm headers so linux/types.h → asm/types.h works
RUN clang -O2 -g -target bpf \
      -I/usr/include \
      -I/usr/include/aarch64-linux-gnu \
      -I/usr/include/aarch64-linux-gnu/asm \
      $(pkg-config --cflags libbpf) \
      -c hook_funcs.bpf.c -o hook_funcs.bpf.o


### Stage 2: build Go server + loader ###
FROM golang:1.24-bookworm AS go-builder

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      libbpf-dev libelf-dev pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY --from=bpf-builder /src/hook_funcs.bpf.o bpf/hook_funcs.bpf.o
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN mkdir -p /out

# build the HTTP server (no cgo)
RUN cd cmd/server && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
      go build -gcflags="-l" -o /out/server_binary

# build the loader (with libbpf cgo)
RUN cd cmd/loader && \
    CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
      CGO_CFLAGS="$(pkg-config --cflags libbpf)" \
      CGO_LDFLAGS="$(pkg-config --libs libbpf)" \
      go build -trimpath -o /out/loader


### Stage 3: runtime image ###
FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      libbpf1 libelf1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=bpf-builder /src/hook_funcs.bpf.o   .
COPY --from=go-builder  /out/server_binary      .
COPY --from=go-builder  /out/loader             .
COPY govuln.json                            .

EXPOSE 8080 2112

# Run both server_binary and loader, probing server_binary
ENTRYPOINT ["/bin/sh", "-c", "./server_binary & ./loader /app/server_binary"]