# claude-feat: media
# claude-feat-md: ffmpeg, imagemagick, webp

RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg imagemagick webp \
    && rm -rf /var/lib/apt/lists/*
