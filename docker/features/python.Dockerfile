# claude-feat: python
# claude-feat-md: Python dev tooling: mypy, ruff, black, pytest, ipython, pyright
# claude-feat-lsp: {"pyright": {"command": "pyright-langserver", "args": ["--stdio"], "extensionToLanguage": {".py": "python", ".pyi": "python"}}}

# Python 3 and uv are already in the base image, other features rely on them,
# so nothing is installed for the interpreter here, only the dev tooling
RUN uv pip install --system --break-system-packages \
    mypy==2.4.1 \
    ruff==0.17.5 \
    black==26.10.1 \
    pytest==9.2.0 \
    ipython==9.18.1

# pyright, the language server behind Claude Code's pyright-lsp plugin. From
# npm, the PyPI package of the same name only downloads this one on first
# run, which the read-only container cannot do.
ARG PYRIGHT_VERSION=1.1.414
RUN npm install -g "pyright@${PYRIGHT_VERSION}" \
    && npm cache clean --force
