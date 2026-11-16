# claude-feat: cpp
# claude-feat-md: cmake, clangd (gcc/g++/make are in the base)
# claude-feat-lsp: {"clangd": {"command": "clangd", "args": ["--background-index"], "extensionToLanguage": {".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hxx": "cpp", ".C": "cpp", ".H": "cpp"}}}

# clangd is the language server behind Claude Code's clangd-lsp plugin
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clangd \
    && rm -rf /var/lib/apt/lists/*
