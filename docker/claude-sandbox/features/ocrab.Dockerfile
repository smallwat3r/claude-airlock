# claude: Ocrab font (system font, usable from Typst and Chromium)
# https://github.com/smallwat3r/ocrab-font, pinned to a release tag and
# checksum-verified (sha256sum of the downloaded fonts/ocrab.otf)
ARG OCRAB_VERSION=1.0.4
ARG OCRAB_SHA256=af49c6c6f72568c62a0243df25b5912e8e3a7a73c3200284d4d8a49e29abab07
RUN mkdir -p /usr/share/fonts/opentype/ocrab \
    && curl -fsSL "https://raw.githubusercontent.com/smallwat3r/ocrab-font/${OCRAB_VERSION}/fonts/ocrab.otf" \
    -o /usr/share/fonts/opentype/ocrab/ocrab.otf \
    && echo "${OCRAB_SHA256}  /usr/share/fonts/opentype/ocrab/ocrab.otf" | sha256sum -c -
