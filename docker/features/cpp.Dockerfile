# claude-feat: cpp
# claude-feat-md: cmake, clangd (gcc/g++/make are in the base)

# clangd is the language server behind Claude Code's clangd-lsp plugin
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clangd \
    && rm -rf /var/lib/apt/lists/*
