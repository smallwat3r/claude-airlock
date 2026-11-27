# claude-feat: playwright
# claude-feat-md: Playwright (Python) with headless Chromium, for PNG diagram export

# Playwright, named in playwright/requirements.in and locked by hash in
# playwright/requirements.txt. The Chromium build follows its version.
COPY playwright/requirements.txt /tmp/playwright-requirements.txt
RUN uv pip install --system --break-system-packages --no-cache \
    --require-hashes -r /tmp/playwright-requirements.txt \
    && rm /tmp/playwright-requirements.txt

# Chromium is kept in the image rather than the default ~/.cache/ms-playwright,
# which is mounted over at runtime. Playwright downloads it over HTTPS and
# checks its size alone, there is no checksum of it to check.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
RUN playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
