# claude: KiCad 9 (kicad-cli, pcbnew Python module, symbol and footprint libraries, no 3D models), headless only
# Bookworm's own kicad is 6.x without kicad-cli, so take it from backports in
# its own install so -t does not pull anything else from there. The 3D model
# package (kicad-packages3d, several GB) is a recommend and deliberately left out.
RUN CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")" \
    && echo "deb http://deb.debian.org/debian ${CODENAME}-backports main" \
    > /etc/apt/sources.list.d/backports.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends -t "${CODENAME}-backports" kicad \
    && rm -rf /var/lib/apt/lists/*
