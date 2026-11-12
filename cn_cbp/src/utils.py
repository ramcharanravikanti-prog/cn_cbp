"""
Utility functions and protocol mappings for DNS traffic analysis.
Provides robust domain normalization, record type lookups, response code descriptions,
and data formatting helpers.
"""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

# Standard DNS Query / Resource Record Types (RFC 1035, RFC 3596, RFC 9460)
DNS_RECORD_TYPES: Dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    51: "NSEC3PARAM",
    52: "TLSA",
    64: "SVCB",
    65: "HTTPS",
    250: "TSIG",
    251: "IXFR",
    252: "AXFR",
    255: "ANY",
}

# Reverse mapping: record type name to integer code
DNS_TYPE_TO_CODE: Dict[str, int] = {v: k for k, v in DNS_RECORD_TYPES.items()}

# Standard DNS Response Codes (RCODE) and technical explanations
DNS_RCODES: Dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
    16: "BADVERS",
}

DNS_RCODE_DESCRIPTIONS: Dict[int, str] = {
    0: "No Error - Successful query completion",
    1: "Format Error - Server was unable to interpret query",
    2: "Server Failure - Server failed to process request due to a resolver/authoritative error",
    3: "Non-Existent Domain - The queried domain does not exist in the DNS zone",
    4: "Not Implemented - Queried request kind is not supported by name server",
    5: "Query Refused - Server refused to answer for policy reasons (e.g. recursion disallowed)",
    6: "Name Exists when it should not (Dynamic Update)",
    7: "RR Set Exists when it should not (Dynamic Update)",
    8: "RR Set that should exist does not (Dynamic Update)",
    9: "Server Not Authoritative for zone / Not Authorized",
    10: "Name not contained in zone (Dynamic Update)",
    16: "Bad OPT Version or TSIG Signature Failure",
}

# DNS OpCodes
DNS_OPCODES: Dict[int, str] = {
    0: "QUERY",
    1: "IQUERY",
    2: "STATUS",
    4: "NOTIFY",
    5: "UPDATE",
}


def normalize_domain(domain_raw: Any) -> str:
    """
    Normalizes a domain name for consistent aggregation and querying.
    - Decodes bytes to string if needed
    - Strips leading and trailing whitespaces
    - Converts to lowercase
    - Strips trailing root dot (e.g., 'example.com.' -> 'example.com')
    - Preserves internal dots and subdomains
    """
    if domain_raw is None:
        return ""

    if isinstance(domain_raw, bytes):
        try:
            domain_str = domain_raw.decode("utf-8", errors="replace")
        except Exception:
            domain_str = str(domain_raw)
    else:
        domain_str = str(domain_raw)

    cleaned = domain_str.strip()
    # Scapy DNS names sometimes have representations like b'example.com.'
    if (cleaned.startswith("b'") and cleaned.endswith("'")) or (cleaned.startswith('b"') and cleaned.endswith('"')):
        cleaned = cleaned[2:-1]

    cleaned = cleaned.lower()
    # Remove trailing dot if present (DNS root notation)
    if cleaned.endswith(".") and len(cleaned) > 1:
        cleaned = cleaned[:-1]

    # Clean unprintable control characters if any
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", cleaned)

    return cleaned


def get_record_type_name(qtype: Union[int, str, None]) -> str:
    """
    Converts a DNS record type integer or string to a standard uppercase record type name.
    """
    if qtype is None:
        return "UNKNOWN"

    if isinstance(qtype, int):
        return DNS_RECORD_TYPES.get(qtype, f"TYPE_{qtype}")

    if isinstance(qtype, str):
        cleaned = qtype.strip().upper()
        if cleaned.isdigit():
            code = int(cleaned)
            return DNS_RECORD_TYPES.get(code, f"TYPE_{code}")
        return cleaned

    return str(qtype).upper()


def get_record_type_code(qtype_name: str) -> Optional[int]:
    """
    Converts a record type name string (e.g., 'AAAA') to its numeric code.
    """
    cleaned = qtype_name.strip().upper()
    return DNS_TYPE_TO_CODE.get(cleaned)


def get_rcode_name(rcode: Union[int, str, None]) -> str:
    """
    Converts a DNS response code integer or string to its standard identifier.
    """
    if rcode is None:
        return "UNKNOWN"

    if isinstance(rcode, int):
        return DNS_RCODES.get(rcode, f"RCODE_{rcode}")

    if isinstance(rcode, str):
        cleaned = rcode.strip().upper()
        if cleaned.isdigit():
            return DNS_RCODES.get(int(cleaned), f"RCODE_{cleaned}")
        return cleaned

    return str(rcode).upper()


def get_rcode_description(rcode: Union[int, str, None]) -> str:
    """
    Returns a human-readable educational description of a DNS response code.
    """
    if rcode is None:
        return "Unknown Response Code"

    if isinstance(rcode, int):
        return DNS_RCODE_DESCRIPTIONS.get(rcode, f"Response Code {rcode}")

    if isinstance(rcode, str) and rcode.isdigit():
        return DNS_RCODE_DESCRIPTIONS.get(int(rcode), f"Response Code {rcode}")

    return f"Response: {rcode}"


def format_timestamp(ts: Union[float, int, datetime, None], include_ms: bool = True) -> str:
    """
    Formats a Unix epoch timestamp or datetime to a consistent ISO 8601 string.
    """
    if ts is None:
        return "N/A"

    if isinstance(ts, (float, int)):
        try:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return "Invalid Timestamp"
    elif isinstance(ts, datetime):
        dt = ts
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    else:
        return str(ts)

    if include_ms:
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def format_latency(latency_ms: Optional[float]) -> str:
    """
    Formats a latency value in milliseconds.
    """
    if latency_ms is None or latency_ms < 0:
        return "N/A"
    if latency_ms < 1.0:
        return f"{latency_ms:.3f} ms"
    return f"{latency_ms:.2f} ms"


def sanitize_text(text: Any) -> str:
    """
    Escapes HTML characters in user or packet text to prevent XSS or display breakage.
    """
    if text is None:
        return ""
    return html.escape(str(text))
