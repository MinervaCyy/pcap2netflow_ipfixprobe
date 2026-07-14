ARG BASE_IMAGE=ubuntu:24.04
ARG BASE_IMAGE_DIGEST=sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

FROM ${BASE_IMAGE}@${BASE_IMAGE_DIGEST} AS builder

ARG DEBIAN_FRONTEND=noninteractive

ARG IPFIXPROBE_REPOSITORY=https://github.com/CESNET/ipfixprobe.git
ARG IPFIXPROBE_COMMIT=f0f16888c426eced7adeed8fc2158362aca1a271

ARG LIBFDS_REPOSITORY=https://github.com/CESNET/libfds.git
ARG LIBFDS_COMMIT=0f148edede1743d6961527965930cf558e9a411e

ARG IPFIXCOL2_REPOSITORY=https://github.com/CESNET/ipfixcol2.git
ARG IPFIXCOL2_COMMIT=4fffd44fbe6ecfe7ae7ad88d2caf53f83a3dd1d0

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    make \
    cmake \
    gcc-14 \
    g++-14 \
    pkg-config \
    rpm \
    libunwind-dev \
    liblz4-dev \
    libssl-dev \
    libfuse3-dev \
    libatomic1 \
    libpcap-dev \
    libxml2-dev \
    libzstd-dev \
    zlib1g-dev \
    librdkafka-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN git clone --filter=blob:none "${IPFIXPROBE_REPOSITORY}" ipfixprobe \
    && git -C ipfixprobe checkout --detach "${IPFIXPROBE_COMMIT}" \
    && test "$(git -C ipfixprobe rev-parse HEAD)" = "${IPFIXPROBE_COMMIT}"

RUN cmake \
      -S /src/ipfixprobe \
      -B /build/ipfixprobe \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=gcc-14 \
      -DCMAKE_CXX_COMPILER=g++-14 \
      -DENABLE_INPUT_PCAP=ON \
    && cmake --build /build/ipfixprobe -j"$(nproc)" \
    && DESTDIR=/stage cmake --install /build/ipfixprobe

RUN git clone --filter=blob:none "${LIBFDS_REPOSITORY}" libfds \
    && git -C libfds checkout --detach "${LIBFDS_COMMIT}" \
    && test "$(git -C libfds rev-parse HEAD)" = "${LIBFDS_COMMIT}"

RUN cmake \
      -S /src/libfds \
      -B /build/libfds \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=gcc-14 \
      -DCMAKE_CXX_COMPILER=g++-14 \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build /build/libfds -j"$(nproc)" \
    && DESTDIR=/stage cmake --install /build/libfds

RUN git clone --filter=blob:none "${IPFIXCOL2_REPOSITORY}" ipfixcol2 \
    && git -C ipfixcol2 checkout --detach "${IPFIXCOL2_COMMIT}" \
    && test "$(git -C ipfixcol2 rev-parse HEAD)" = "${IPFIXCOL2_COMMIT}"

RUN PKG_CONFIG_PATH=/stage/usr/local/lib/pkgconfig \
    CMAKE_PREFIX_PATH=/stage/usr/local \
    LD_LIBRARY_PATH=/stage/usr/local/lib \
    cmake \
      -S /src/ipfixcol2 \
      -B /build/ipfixcol2 \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=gcc-14 \
      -DCMAKE_CXX_COMPILER=g++-14 \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DENABLE_DOC_MANPAGE=OFF \
      -DENABLE_DOC_DOXYGEN=OFF \
      -DENABLE_TESTS=OFF \
    && PKG_CONFIG_PATH=/stage/usr/local/lib/pkgconfig \
       CMAKE_PREFIX_PATH=/stage/usr/local \
       LD_LIBRARY_PATH=/stage/usr/local/lib \
       cmake --build /build/ipfixcol2 -j"$(nproc)" \
    && DESTDIR=/stage cmake --install /build/ipfixcol2

FROM ${BASE_IMAGE}@${BASE_IMAGE_DIGEST}

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libunwind8 \
    liblz4-1 \
    libssl3t64 \
    libfuse3-3 \
    libatomic1 \
    libpcap0.8t64 \
    libxml2 \
    libzstd1 \
    zlib1g \
    librdkafka1 \
    fuse3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /stage/usr/local/ /usr/local/

RUN printf '%s\n' '/usr/local/lib' > /etc/ld.so.conf.d/pcap2netflow.conf \
    && ldconfig

COPY docker/entrypoint.sh /usr/local/bin/pcap2netflow-entrypoint
RUN chmod +x /usr/local/bin/pcap2netflow-entrypoint

ENTRYPOINT ["/usr/local/bin/pcap2netflow-entrypoint"]
CMD ["--version"]
