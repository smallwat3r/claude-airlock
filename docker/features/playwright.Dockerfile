# claude: Playwright (Python) with headless Chromium, for PNG diagram export
# The Chromium build follows the pinned playwright version
RUN uv pip install --system --break-system-packages playwright==1.65.1

# Chromium is kept in the image rather than the default ~/.cache/ms-playwright,
# which is mounted over at runtime
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
RUN playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
