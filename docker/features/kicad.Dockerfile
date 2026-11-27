# claude-feat: kicad
# claude-feat-md: KiCad 9 (kicad-cli, pcbnew Python module, symbol and footprint libraries, no 3D models), headless only

# Bookworm's own kicad is 6.x without kicad-cli, so take it from backports in
# its own install so -t does not pull anything else from there. The symbol
# and footprint libraries are a recommend of kicad, kicad-libraries, so it
# is named. The 3D models (kicad-packages3d, several GB) are only suggested
# by either and deliberately left out.
RUN CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")" \
    && echo "deb http://deb.debian.org/debian ${CODENAME}-backports main" \
    > /etc/apt/sources.list.d/backports.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends -t "${CODENAME}-backports" \
    kicad \
    kicad-libraries \
    && rm -rf /var/lib/apt/lists/*
