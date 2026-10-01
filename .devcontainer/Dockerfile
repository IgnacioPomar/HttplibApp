FROM debian:13-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        ninja-build \
        clang-format \
        clang-tidy \
        gdb \
        ccache \
        python3 python3-venv python3-pip \
        git \
        openssh-client \
        curl \
        ca-certificates \
        pkg-config

RUN python3 -m venv /opt/conan-env \
    && /opt/conan-env/bin/pip install --no-cache-dir "conan>=2.0"

ENV PATH="/opt/conan-env/bin:/usr/lib/ccache:$PATH"

RUN groupadd --gid 1000 vscode \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash vscode \
    && chown -R vscode:vscode /opt/conan-env

WORKDIR /workspace
RUN chown vscode:vscode /workspace

USER vscode
