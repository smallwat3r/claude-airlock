# claude-feat: reverse
# claude-feat-md: Reverse engineering: gdb-multiarch, binutils-multiarch (objdump, readelf, nm for foreign architectures), strace, ltrace (not on arm64), binwalk, squashfs-tools, xxd, Python capstone, lief, pyelftools

# Static analysis of binaries and firmware, plus tracing of processes started
# from inside the sandbox. radare2 and rizin are not packaged for bookworm and
# Ghidra needs a JDK (over 1 GB together), so they are left out. Debian does
# not build ltrace for every architecture (arm64 has none in bookworm), so it
# is only installed where apt offers it.
RUN apt-get update \
    && LTRACE="$(apt-cache show ltrace >/dev/null 2>&1 && echo ltrace || true)" \
    && apt-get install -y --no-install-recommends \
    gdb-multiarch \
    binutils-multiarch \
    strace \
    ${LTRACE} \
    binwalk \
    squashfs-tools \
    file \
    xxd \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Disassembly and executable parsing (ELF, PE, Mach-O) from Python
RUN uv pip install --system --break-system-packages --no-cache \
    capstone==5.0.9 \
    lief==1.0.0 \
    pyelftools==0.33
