# claude-feat: font
# claude-feat-md: Font tooling: fontforge (headless, -script or its Python module), fonttools, ttfautohint, woff2, fontconfig
# claude-feat-md: Ocrab font (system font, usable from Typst and Chromium)

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
RUN uv pip install --system --break-system-packages \
    fonttools==4.68.0 \
    brotli==1.2.1

# https://github.com/smallwat3r/ocrab-font, pinned to a release tag and
# checksum-verified (sha256sum of the downloaded fonts/ocrab.otf)
ARG OCRAB_VERSION=1.0.4
ARG OCRAB_SHA256=af49c6c6f72568c62a0243df25b5912e8e3a7a73c3200284d4d8a49e29abab07
RUN mkdir -p /usr/share/fonts/opentype/ocrab \
    && curl -fsSL "https://raw.githubusercontent.com/smallwat3r/ocrab-font/${OCRAB_VERSION}/fonts/ocrab.otf" \
    -o /usr/share/fonts/opentype/ocrab/ocrab.otf \
    && echo "${OCRAB_SHA256}  /usr/share/fonts/opentype/ocrab/ocrab.otf" | sha256sum -c -
