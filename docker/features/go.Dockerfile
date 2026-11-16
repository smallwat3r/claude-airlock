# claude-feat: go
# claude-feat-md: Go with gopls (GOPATH is ~/.cache/go)
# claude-feat-lsp: {"gopls": {"command": "gopls", "extensionToLanguage": {".go": "go"}}}

# Official tarball (apt's is outdated), pinned and checksum-verified. The shas
# are recorded on purpose: fetching them from the same server as the artifact
# would verify nothing. Update version and shas from https://go.dev/dl
ARG GO_VERSION=go1.27.4
ARG GO_SHA256_AMD64=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
ARG GO_SHA256_ARM64=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92
RUN ARCH="$(dpkg --print-architecture)" \
    && case "${ARCH}" in \
    amd64) GO_SHA256="${GO_SHA256_AMD64}" ;; \
    arm64) GO_SHA256="${GO_SHA256_ARM64}" ;; \
    *) echo "unsupported arch: ${ARCH}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://go.dev/dl/${GO_VERSION}.linux-${ARCH}.tar.gz" \
    -o /tmp/go.tar.gz \
    && echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

# The default GOPATH (~/go) sits on the read-only root filesystem, where the
# module cache could never be written. ~/.cache is writable.
ENV GOPATH=/home/node/.cache/go
ENV PATH="/usr/local/go/bin:/home/node/.cache/go/bin:${PATH}"

# gopls, the language server behind Claude Code's gopls-lsp plugin. Installed
# to /usr/local/bin because GOPATH is mounted over at runtime, with a
# throwaway GOPATH and build cache so neither stays in the image. go install
# verifies the module against the Go checksum database.
ARG GOPLS_VERSION=v0.24.0
RUN GOBIN=/usr/local/bin GOPATH=/tmp/gopath GOCACHE=/tmp/gocache \
    go install "golang.org/x/tools/gopls@${GOPLS_VERSION}" \
    && rm -rf /tmp/gopath /tmp/gocache
