FROM debian:stable-slim as builder
WORKDIR /src
ENV LANG="C.UTF-8"
ENV TERM=xterm
ARG target=""
ONBUILD ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y \
         build-essential \
         libsnmp-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN ./configure --libexecdir=/src \
    && make $target

FROM debian:stable-slim
ONBUILD ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y \
         libsnmp30 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=0 /src/check_interfaces /check_interfaces

ENTRYPOINT ["/check_interfaces"]
