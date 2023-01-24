FROM golang:1.18-alpine as builder

WORKDIR /build

RUN apt update && apt install -y \
    libseccomp-dev \
    gcc \
    make \
    lsb-release \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /chroot && \
    mkdir /chroot/dev && \
    cp -r /bin /chroot/ && \
    cp -r /sbin /chroot/ && \
    cp -r /usr /chroot/ && \
    cp -r /etc /chroot/ && \
    cp -r /lib /chroot/ && \
    cp -r /lib64 /chroot/

COPY . /build

RUN make

RUN cp capejail /bin/

RUN useradd jailuser
