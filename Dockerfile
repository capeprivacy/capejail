FROM debian:bullseye-slim as builder

WORKDIR /build

RUN apt update && apt install -y \
    libseccomp-dev \
    gcc \
    make

COPY . /build

RUN make -j$(nproc)

FROM debian:bullseye-slim

COPY --from=builder /build/seccomp  /

ENTRYPOINT [ "/seccomp" ]
