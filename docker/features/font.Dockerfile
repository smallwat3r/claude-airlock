# claude-feat: font
# claude-feat-md: Font tooling: fontforge (headless, -script or its Python module), fonttools, ttfautohint, woff2, fontconfig
# claude-feat-md: Monospace fonts (system fonts, usable from Typst and Chromium): DejaVu Sans Mono, Liberation Mono, Noto Mono, JetBrains Mono, Fira Code, Hack, Inconsolata, Anonymous Pro, Courier Prime, Mononoki, Go Mono

# fontforge-nox is the build without the X11 GUI, the sandbox has no display.
# python3-fontforge binds to Debian's python3, the interpreter of the base.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    fontforge-nox \
    python3-fontforge \
    ttfautohint \
    woff2 \
    fontconfig \
    && rm -rf /var/lib/apt/lists/*

# From PyPI, bookworm's fonttools is years behind. brotli is what gives
# fonttools its WOFF2 support.
RUN uv pip install --system --break-system-packages --no-cache \
    fonttools==4.68.0 \
    brotli==1.2.1

# The common monospace fonts bookworm packages. fonts-dejavu-core,
# fonts-liberation2 and fonts-go bring their proportional families too.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    fonts-dejavu-core \
    fonts-liberation2 \
    fonts-noto-mono \
    fonts-jetbrains-mono \
    fonts-firacode \
    fonts-hack \
    fonts-inconsolata \
    fonts-anonymous-pro \
    fonts-courier-prime \
    fonts-mononoki \
    fonts-go \
    && rm -rf /var/lib/apt/lists/* \
    && fc-cache -f
