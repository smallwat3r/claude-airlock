# claude-feat: excalidraw
# claude-feat-requires: playwright
# claude-feat-md: Excalidraw diagrams, offline: excalidraw-export SCENE OUT.png renders one and takes the scene back out of a picture to edit it. Read excalidraw-export --help before the first use, for the scene format and what to avoid

# Excalidraw only runs in a browser, so the export drives the headless
# Chromium of the playwright feature, hence the requirement above

# The package is made for bundlers and loads its fonts over the network. A
# session may have neither npm access nor a route out, so it is bundled into
# one script here and the fonts are kept next to it. React is a peer
# dependency the export never renders with, it follows the major Excalidraw
# was built for and is not refreshed by update-pins.py.
ARG EXCALIDRAW_VERSION=0.18.1
ARG EXCALIDRAW_ESBUILD_VERSION=0.28.2
RUN mkdir -p /opt/excalidraw /tmp/excalidraw-build \
    && cd /tmp/excalidraw-build \
    && npm install --no-audit --no-fund \
    "@excalidraw/excalidraw@${EXCALIDRAW_VERSION}" \
    "esbuild@${EXCALIDRAW_ESBUILD_VERSION}" \
    react@18.3.1 \
    react-dom@18.3.1 \
    && echo 'export {convertToExcalidrawElements, exportToBlob, exportToSvg, loadFromBlob, serializeAsJSON} from "@excalidraw/excalidraw";' > entry.js \
    && ./node_modules/.bin/esbuild entry.js --bundle --minify --format=iife \
    --global-name=Excalidraw --log-level=error \
    '--define:process.env.NODE_ENV="production"' \
    '--define:import.meta.env={"PROD":true,"MODE":"production"}' \
    --outfile=/opt/excalidraw/excalidraw.js \
    && cp -r node_modules/@excalidraw/excalidraw/dist/prod/fonts /opt/excalidraw/fonts \
    && cd / \
    && rm -rf /tmp/excalidraw-build \
    && npm cache clean --force

# From the directory named after this feature, which the launcher adds to
# the build context
COPY excalidraw/excalidraw-export /usr/local/bin/excalidraw-export
RUN chmod 755 /usr/local/bin/excalidraw-export
