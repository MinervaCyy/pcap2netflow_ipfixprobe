ARG BASE_IMAGE=ubuntu:24.04
ARG BASE_IMAGE_DIGEST=sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

FROM ${BASE_IMAGE}@${BASE_IMAGE_DIGEST} AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG IPFIXPROBE_REPOSITORY=https://github.com/CESNET/ipfixprobe.git
ARG IPFIXPROBE_COMMIT=f0f16888c426eced7adeed8fc2158362aca1a271

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

FROM ${BASE_IMAGE}@${BASE_IMAGE_DIGEST}

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libunwind8 \
    liblz4-1 \
    libssl3t64 \
    libfuse3-3 \
    libatomic1 \
    libpcap0.8t64 \
    fuse3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /stage/usr/local/ /usr/local/


COPY docker/entrypoint.sh /usr/local/bin/pcap2netflow-entrypoint
RUN chmod +x /usr/local/bin/pcap2netflow-entrypoint

ENTRYPOINT ["/usr/local/bin/pcap2netflow-entrypoint"]
CMD ["--version"]
