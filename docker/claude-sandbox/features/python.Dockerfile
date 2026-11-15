# claude: Python dev tooling: mypy, ruff, black, pytest, ipython
# Python 3 and uv are already in the base image, other features rely on them,
# so nothing is installed for the interpreter here, only the dev tooling
RUN uv pip install --system --break-system-packages \
    mypy==2.4.1 \
    ruff==0.17.5 \
    black==26.10.1 \
    pytest==9.2.0 \
    ipython==9.18.1
