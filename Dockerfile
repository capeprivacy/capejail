FROM golang:1.18-alpine as builder

WORKDIR /build

RUN apk add libseccomp-dev

COPY . /build

RUN go build . 

RUN cp capejail /bin/


FROM python:3.9-slim-bullseye

WORKDIR /runtime

# Add some pre-bundled python libraries.
RUN pip install python-dotenv
RUN pip install pyjwt[crypto]
RUN apt update && \
    apt install -y \
    gcc \
    python3-dev \
    python3-pip \
    wget

## OCR-specific dependencies ##
# the following are ocrmypdf and pdf2image dependencies
RUN apt install -y \
    ghostscript \
    icc-profiles-free \
    libxml2 \
    pngquant \
    python3-pip \
    tesseract-ocr \
    zlib1g

# jbig2enc is an extra dependency for ocrmypdf that improves image quality
# we have to build it from source bc the Bullseye version is outdated
RUN apt install -y \
    # jbig2enc deps
    libtool libleptonica-dev \
    # jbig2enc build deps
    git build-essential \
    && apt clean

# build jbig2enc
RUN git clone https://github.com/agl/jbig2enc
RUN cd jbig2enc && ./autogen.sh
RUN cd jbig2enc && ./configure
RUN cd jbig2enc && make && make install

# Install ghostscript 10. This fixes a bug in 9.53 from Debian Bullseye
# RUN apt install -y ghostscript
RUN wget https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs1000/ghostscript-10.0.0-linux-x86_64.tgz
RUN tar -xf ghostscript-10.0.0-linux-x86_64.tgz
RUN cp ghostscript-10.0.0-linux-x86_64/gs-1000-linux-x86_64 /usr/bin/gs

WORKDIR /runtime

COPY ./ocr /runtime/ocr
COPY ./seccomp.yml /runtime/ocr/.

COPY --from=builder /bin/capejail ./ocr/capejail
CMD [ "/runtime/ocr/capejail", "python", "app.py" ]
