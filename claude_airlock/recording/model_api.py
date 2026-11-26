"""Where Claude Code sends the conversation, again with every step: the
addresses Anthropic publishes for its API. Told by address, a name is the
session's to choose. Asked by what says a lot was sent somewhere (see
report/digest.py), which leaves the model's API out, and by the capture,
which takes what a session sends there to tell its requests apart (see
uploads.py)."""

from __future__ import annotations

import ipaddress

MODEL_API = (
    ipaddress.ip_network("160.79.104.0/23"),
    ipaddress.ip_network("2607:6bc0::/48"),
)
MODEL_DOMAIN = "anthropic.com"


def is_model_api(address: str) -> bool:
    """Whether an address is one of the model's API."""
    try:
        found = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(found in network for network in MODEL_API)


def is_model_host(host: str) -> bool:
    """The same by name, as a filtered session asks its proxy for it."""
    return host == MODEL_DOMAIN or host.endswith("." + MODEL_DOMAIN)
