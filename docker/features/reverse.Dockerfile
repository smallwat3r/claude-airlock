# claude-feat: reverse
# claude-feat-md: Reverse engineering: gdb-multiarch, binutils-multiarch (objdump, readelf, nm for foreign architectures such as ARM firmware), strace, ltrace, binwalk, squashfs-tools, file, xxd, unzip, Python capstone, lief, pyelftools

# Static analysis of binaries and firmware, plus tracing of processes started
# from inside the sandbox. radare2 and rizin are not packaged for bookworm and
# Ghidra needs a JDK (over 1 GB together), so they are left out.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    gdb-multiarch \
    binutils-multiarch \
    strace \
    ltrace \
    binwalk \
    squashfs-tools \
    file \
    xxd \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Disassembly and executable parsing (ELF, PE, Mach-O) from Python
RUN uv pip install --system --break-system-packages \
    capstone==5.0.9 \
    lief==1.0.0 \
    pyelftools==0.33
