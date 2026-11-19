# claude-feat: ble
# claude-feat-md: BLE capture analysis, offline only (the container has no Bluetooth adapter): tshark for btsnoop and pcap files, Python scapy

# The sandbox has no access to the host's Bluetooth stack, so this covers
# captures taken elsewhere (Android btsnoop_hci.log, nRF Sniffer pcap), not
# live scanning. DEBIAN_FRONTEND keeps wireshark-common's setuid question quiet.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

# HCI, L2CAP, ATT and SMP dissection and crafting from Python
RUN uv pip install --system --break-system-packages --no-cache \
    scapy==2.8.0
