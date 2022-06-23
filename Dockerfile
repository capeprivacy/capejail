FROM debian:bullseye-slim as builder

WORKDIR /build

RUN apt update && apt install -y \
    libseccomp-dev \
    gcc \
    make \
    lsb-release \
    wget \
    gnupg \
    software-properties-common

RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 14

RUN  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

RUN apt update && apt install -y \
    clang-14 \
    clang-tools-14 \
    clang-14-doc \
    libclang-common-14-dev \
    libclang-14-dev \
    libclang1-14 \
    clang-format-14 \
    python3-clang-14 \
    clangd-14 \
    clang-tidy-14

RUN ln -s /usr/bin/clang-format-14 /usr/bin/clang-format

RUN mkdir /chroot && \
    mkdir /chroot/dev && \
    cp -r /bin /chroot/ && \
    cp -r /sbin /chroot/ && \
    cp -r /usr /chroot/ && \
    cp -r /etc /chroot/ && \
    cp -r /lib /chroot/ && \
    cp -r /lib64 /chroot/

COPY . /build

RUN make -j$(nproc)

RUN cp capejail /bin/

RUN useradd jailuser
