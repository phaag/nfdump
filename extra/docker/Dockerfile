ARG ALPINE_VERSION=3
FROM alpine:${ALPINE_VERSION} AS builder

# Assume context is root of nfdump repository
COPY . /app
RUN apk add --no-cache build-base gcc abuild binutils make \
  libtool bzip2-dev libpcap-dev flex bison libbsd-dev \
  autoconf automake m4 pkgconfig

WORKDIR /app

RUN ./autogen.sh \
  && ./configure --enable-native --enable-lto \
    --enable-maxmind --enable-nfpcapd \
    --enable-sflow=yes --with-lz4path=/usr \
    --with-zstdpath=/usr --with-bz2path=/usr \
  && make CPPFLAGS="-include bsd/stdlib.h" && make install

FROM alpine:${ALPINE_VERSION} AS base

RUN apk add --no-cache bzip2-dev libpcap-dev lz4-libs zstd libbsd

COPY --from=builder /usr/local /usr/local

# Run as non-root
RUN addgroup -S nfdump -g 1000 \
  && adduser -h /home/nfdump -S nfdump -G nfdump -u 1000

RUN mkdir -p /data && chown -R nfdump:nfdump /data
VOLUME /data

USER nfdump

FROM base AS nfcapd

EXPOSE 9995/udp

ENTRYPOINT ["/usr/local/bin/nfcapd"]

CMD ["-w", "/data", "-S", "1", "-y", "-p", "9995"]

FROM base AS nfdump

ENTRYPOINT ["/bin/ash"]
