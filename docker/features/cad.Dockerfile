# claude-feat: cad
# claude-feat-md: openscad, admesh (3D / CAD, headless only)

RUN apt-get update \
    && apt-get install -y --no-install-recommends openscad admesh \
    && rm -rf /var/lib/apt/lists/*

# Let openscad render headless (no display) via the CLI
ENV QT_QPA_PLATFORM=offscreen
