# claude: pandoc, poppler-utils (pdftotext, pdfunite, pdftoppm...), qpdf, gnuplot
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    pandoc \
    poppler-utils \
    qpdf \
    gnuplot \
    && rm -rf /var/lib/apt/lists/*
