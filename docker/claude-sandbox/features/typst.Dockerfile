# claude: typst
# Official musl tarball, pinned and checksum-verified. Update from
# https://github.com/typst/typst/releases (no upstream checksum files, so
# compute sha256sum on the downloaded tarballs)
ARG TYPST_VERSION=v0.15.1
ARG TYPST_SHA256_AMD64=a6d077d0a95eed5a2eba715b2dae06be954f624ccbf85758a03f389ded33118c
ARG TYPST_SHA256_ARM64=5aa8d74a3d906e60ea12a66ac2f37f8eef1b14cbad7182a745e393a10c23dcee
RUN apt-get update \
    && apt-get install -y --no-install-recommends xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && ARCH="$(dpkg --print-architecture)" \
    && case "${ARCH}" in \
    amd64) TYPST_ARCH=x86_64; TYPST_SHA256="${TYPST_SHA256_AMD64}" ;; \
    arm64) TYPST_ARCH=aarch64; TYPST_SHA256="${TYPST_SHA256_ARM64}" ;; \
    *) echo "unsupported arch: ${ARCH}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://github.com/typst/typst/releases/download/${TYPST_VERSION}/typst-${TYPST_ARCH}-unknown-linux-musl.tar.xz" \
    -o /tmp/typst.tar.xz \
    && echo "${TYPST_SHA256}  /tmp/typst.tar.xz" | sha256sum -c - \
    && tar -C /usr/local/bin --strip-components=1 -xJf /tmp/typst.tar.xz \
    "typst-${TYPST_ARCH}-unknown-linux-musl/typst" \
    && rm /tmp/typst.tar.xz
