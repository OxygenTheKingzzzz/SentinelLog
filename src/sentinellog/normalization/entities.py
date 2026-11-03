"""Optional IP and username extraction.

A line is kept whether or not either value is present. Extraction is heuristic
and is not a claim about authentication outcome or malice.
"""

import re

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = re.compile(rf"\b{_OCTET}(?:\.{_OCTET}){{3}}\b")
# Avoid matching the "user" inside "ruser=".
_USER_EQ = re.compile(r"(?<![A-Za-z0-9_])user=([^\s,;]+)")
_FOR_USER = re.compile(r"\bfor user ([^\s,;]+)")
_ANONYMOUS = re.compile(r"\((anonymous)\)", re.IGNORECASE)
_ROOT_LOGIN = re.compile(r"^ROOT LOGIN\b")
_REJECT_NAMES = {"", "unknown"}
_MAX_NAME = 256


def extract_ip(content: str) -> str | None:
    match = _IPV4.search(content)
    if match is None:
        return None
    return match.group(0)


def extract_username(content: str) -> str | None:
    equality = _USER_EQ.search(content)
    if equality:
        name = equality.group(1)
        if name not in _REJECT_NAMES and len(name) <= _MAX_NAME:
            return name
    opened = _FOR_USER.search(content)
    if opened:
        name = opened.group(1)
        if name not in _REJECT_NAMES and len(name) <= _MAX_NAME:
            return name
    if _ROOT_LOGIN.search(content):
        return "root"
    anonymous = _ANONYMOUS.search(content)
    if anonymous:
        return "anonymous"
    return None
