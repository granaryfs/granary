# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
FROM localhost/linux-container:latest

# Build and runtime prerequisites from the two suites' READMEs. The image is
# a development tool; no installed file enters a granary release artifact.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git autoconf automake libtool make gcc pkg-config python3 openssl \
        perl libtest-harness-perl bc gawk attr acl xfsprogs xfslibs-dev libcap-dev e2fsprogs \
        libacl1-dev libattr1-dev libaio-dev liburing-dev uuid-dev \
        libgdbm-dev libssl-dev libuuid1 libtool-bin util-linux kmod procps \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/posix-tools.sh /tmp/posix-tools.sh
RUN bash /tmp/posix-tools.sh /opt/posix && rm /tmp/posix-tools.sh
