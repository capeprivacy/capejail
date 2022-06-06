FROM debian:bullseye-slim as builder

WORKDIR /build

RUN apt update && apt install -y \
    libseccomp-dev \
    gcc \
    make

COPY . /build

RUN make -j$(nproc)

FROM debian:bullseye-slim

RUN mkdir /chroot && \
    mkdir /chroot/dev && \
    cp -r /bin /chroot/ && \
    cp -r /sbin /chroot/ && \
    cp -r /usr /chroot/ && \
    cp -r /etc /chroot/ && \
    cp -r /lib /chroot/ && \
    cp -r /lib64 /chroot/

COPY --from=builder /build/capejail  /bin/

RUN useradd jailuser

ENTRYPOINT [ "capejail","-u","jailuser","-r","/chroot","--","/bin/ls","-l" ]
