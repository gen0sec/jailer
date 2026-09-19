# syntax=docker/dockerfile:1.7
#
# The build that produces release artifacts.
#
# Stage map:
#   base    - Ubuntu 20.04 + clang-18 + libbpf headers + rustup
#   builder - compiles the BPF object, then the workspace
#   output  - just the three shipped files, for `--output type=local`
#
# Why a container at all, when CI already builds the workspace: a binary is
# dynamically linked against the glibc it was built on, and that becomes a
# *floor* for every host it runs on. Building on the ubuntu-24.04 runner would
# stamp glibc 2.39 into every release, so it would refuse to start anywhere
# older. Focal's 2.31 is the floor instead, and it is the only thing this image
# is old for -- the compilers are current.
#
# Extract with:
#   docker build --target output --output type=local,dest=./out \
#     -f pkg/docker/build.Dockerfile .

ARG IMAGE="ubuntu"
# 20.04 focal: glibc 2.31.
ARG IMAGE_TAG="20.04"

# ---------------------------------------------------------------- base
FROM ${IMAGE}:${IMAGE_TAG} AS base

# tzdata is pulled in transitively by build-essential and prompts for a region,
# which hangs a non-interactive build forever.
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      curl \
      git \
      gnupg \
      libelf-dev \
      make \
      pkg-config \
      zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Focal ships clang-10, which is too old for the CO-RE macros main.bpf.c uses
# (bpf_core_field_offset, BPF_CORE_READ_BITFIELD_PROBED). bpfjailer-bpf/build.rs
# invokes bare `clang`, so update-alternatives is what points it at clang-18.
ARG LLVM_VERSION=18
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
      | gpg --dearmor -o /etc/apt/trusted.gpg.d/llvm.gpg && \
    echo "deb [signed-by=/etc/apt/trusted.gpg.d/llvm.gpg] http://apt.llvm.org/focal/ llvm-toolchain-focal-${LLVM_VERSION} main" \
      > /etc/apt/sources.list.d/llvm.list && \
    apt-get update && apt-get install -y --no-install-recommends \
      clang-${LLVM_VERSION} \
      llvm-${LLVM_VERSION} && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${LLVM_VERSION} 180 && \
    rm -rf /var/lib/apt/lists/*

# libbpf *headers* only (bpf_helpers.h, bpf_core_read.h, ...). Focal's
# libbpf-dev is 0.1.0 and predates the CO-RE macros; libbpf-sys vendors and
# builds the library itself, so nothing here needs the distro's .so.
# bpfjailer-bpf/build.rs adds -I/usr/include only when /usr/include/bpf exists,
# which is exactly what install_headers creates.
ARG LIBBPF_VERSION=1.3.0
RUN curl -fsSL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" \
      | tar xz -C /tmp && \
    make -C "/tmp/libbpf-${LIBBPF_VERSION}/src" install_headers PREFIX=/usr && \
    rm -rf "/tmp/libbpf-${LIBBPF_VERSION}"

ARG RUST_VERSION=stable
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION}
ENV PATH="/root/.cargo/bin:${PATH}"

# ------------------------------------------------------------- builder
FROM base AS builder
WORKDIR /src
COPY . .

# The BPF object first and on its own: it is produced by bpfjailer-bpf/build.rs
# via clang, and the userspace crates load it at runtime rather than linking it,
# so nothing else in the workspace forces it to be built.
RUN cd bpfjailer-bpf && cargo build --release

RUN cargo build --release --workspace

# Collect the three shipped files. build.rs picks its output directory based on
# whether a workspace-level bpfel target dir already exists, so check both
# rather than assuming -- a release that silently shipped no object, or a stale
# one from a previous layer, is the failure worth spending five lines on.
RUN set -eu; \
    mkdir -p /output; \
    for d in /src/bpfjailer-bpf/target /src/target; do \
      if [ -f "$d/bpfel-unknown-none/release/bpfjailer.bpf.o" ]; then \
        cp "$d/bpfel-unknown-none/release/bpfjailer.bpf.o" /output/; break; \
      fi; \
    done; \
    test -f /output/bpfjailer.bpf.o || { echo "bpfjailer.bpf.o was not produced" >&2; exit 1; }; \
    cp /src/target/release/bpfjailer-bootstrap /output/; \
    cp /src/target/release/bpfjailer-daemon /output/; \
    /output/bpfjailer-bootstrap --version; \
    /output/bpfjailer-daemon --version

# -------------------------------------------------------------- output
FROM scratch AS output
COPY --from=builder /output/ /
