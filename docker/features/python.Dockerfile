# claude-feat: python
# claude-feat-md: Python dev tooling: mypy, ruff, black, pytest, ipython, pyright
# claude-feat-lsp: {"pyright": {"command": "pyright-langserver", "args": ["--stdio"], "extensionToLanguage": {".py": "python", ".pyi": "python"}}}

# Python 3 and uv are already in the base image, other features rely on them,
# so nothing is installed for the interpreter here, only the dev tooling,
# named in python/requirements.in and locked by hash in
# python/requirements.txt
COPY python/requirements.txt /tmp/python-requirements.txt
RUN uv pip install --system --break-system-packages --no-cache \
    --require-hashes -r /tmp/python-requirements.txt \
    && rm /tmp/python-requirements.txt

# pyright, the language server behind Claude Code's pyright-lsp plugin. From
# npm, the PyPI package of the same name only downloads this one on first
# run, which the read-only container cannot do.
ARG PYRIGHT_VERSION=1.1.414
RUN npm install -g "pyright@${PYRIGHT_VERSION}" \
    && npm cache clean --force
