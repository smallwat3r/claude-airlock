# claude-feat: go
# claude-feat-md: Go with gopls (GOPATH is ~/.cache/go)
# claude-feat-lsp: {"gopls": {"command": "gopls", "extensionToLanguage": {".go": "go"}}}

# Official tarball (apt's is outdated), pinned and checksum-verified. The shas
# are recorded on purpose: fetching them from the same server as the artifact
# would verify nothing. Update version and shas from https://go.dev/dl
ARG GO_VERSION=go1.27.1
ARG GO_SHA256_AMD64=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
ARG GO_SHA256_ARM64=3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec
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
