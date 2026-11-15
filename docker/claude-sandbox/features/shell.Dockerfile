# claude: shellcheck, shfmt
RUN apt-get update \
    && apt-get install -y --no-install-recommends shellcheck shfmt \
    && rm -rf /var/lib/apt/lists/*
