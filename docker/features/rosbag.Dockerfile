# claude-feat: rosbag
# claude-feat-md: Rosbag tooling: mcap CLI, sqlite3 CLI, Python rosbags, mcap, mcap-ros1/ros2-support

# Reading, writing and conversion (ROS1 + ROS2, sqlite3 + mcap storage)
RUN uv pip install --system --break-system-packages --no-cache \
    rosbags==0.11.9 \
    mcap==1.6.0 \
    mcap-ros1-support==0.9.0 \
    mcap-ros2-support==0.6.0

# sqlite3 CLI, to inspect ROS2 .db3 bags directly
RUN apt-get update \
    && apt-get install -y --no-install-recommends sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# mcap CLI (inspect/filter/recover .mcap rosbags), pinned and checksum-verified.
# Update from https://github.com/foxglove/mcap/releases (no upstream checksum
# files, so compute sha256sum on the downloaded binaries)
ARG MCAP_VERSION=v0.4.0
ARG MCAP_SHA256_AMD64=3ace13bc8f0273c69742f25695f7f2df84aed57ddd7c36d5f9a59561dc719fb1
ARG MCAP_SHA256_ARM64=94fd84e40ed1593205caf9b9ccee863181256a2fe1ad051ee55d31b4d1b4aca7
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
