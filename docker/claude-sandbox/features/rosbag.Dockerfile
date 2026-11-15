# claude: Rosbag tooling: mcap CLI, Python rosbags, mcap, mcap-ros1/ros2-support
# Reading, writing and conversion (ROS1 + ROS2, sqlite3 + mcap storage)
RUN uv pip install --system --break-system-packages \
    rosbags==0.11.9 \
    mcap==1.6.0 \
    mcap-ros1-support==0.9.0 \
    mcap-ros2-support==0.6.0

# mcap CLI (inspect/filter/recover .mcap rosbags), pinned and checksum-verified.
# Update from https://github.com/foxglove/mcap/releases (no upstream checksum
# files, so compute sha256sum on the downloaded binaries)
ARG MCAP_VERSION=v0.3.0
ARG MCAP_SHA256_AMD64=5d4100573fab880f1c6400952466275bb3b32c3d230a54f7c380ee0d08e59eef
ARG MCAP_SHA256_ARM64=be9734ef63ada9d0cc7a3aa41378ab65fd482601e5f5b3b52098d8e6553deabf
RUN ARCH="$(dpkg --print-architecture)" \
    && case "${ARCH}" in \
    amd64) MCAP_SHA256="${MCAP_SHA256_AMD64}" ;; \
    arm64) MCAP_SHA256="${MCAP_SHA256_ARM64}" ;; \
    *) echo "unsupported arch: ${ARCH}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://github.com/foxglove/mcap/releases/download/releases/mcap-cli/${MCAP_VERSION}/mcap-linux-${ARCH}" \
    -o /usr/local/bin/mcap \
    && echo "${MCAP_SHA256}  /usr/local/bin/mcap" | sha256sum -c - \
    && chmod +x /usr/local/bin/mcap
