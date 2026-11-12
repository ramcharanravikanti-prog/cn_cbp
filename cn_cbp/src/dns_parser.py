"""
DNS Packet Parser module.
Extracts structured DNS message details from Scapy packets across UDP and TCP,
handling multi-question/multi-answer packets, edge cases, and parsing anomalies.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from src.utils import (
    format_timestamp,
    get_rcode_name,
    get_record_type_name,
    normalize_domain,
)

logger = logging.getLogger(__name__)


@dataclass
class DNSQuestion:
    """Represents a single DNS question entry."""
    qname: str
    qtype: str
    qtype_code: int
    qclass: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DNSAnswer:
    """Represents a single DNS resource record answer."""
    rrname: str
    type: str
    type_code: int
    rdata: str
    ttl: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ParsedDNSMessage:
    """Structured representation of an extracted DNS packet."""
    frame_number: int
    timestamp: float
    timestamp_iso: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ip_version: Optional[int]
    transport_protocol: str  # "UDP" or "TCP"
    transaction_id: int
    is_response: bool  # True if qr == 1, False if qr == 0
    qr_flag: int  # 0: query, 1: response
    opcode: int
    aa: int  # Authoritative Answer
    tc: int  # Truncation
    rd: int  # Recursion Desired
    ra: int  # Recursion Available
    rcode: int  # Response Code
    rcode_name: str
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    questions: List[Dict[str, Any]] = field(default_factory=list)
    primary_qname: str = ""
    primary_qtype: str = ""
    answers: List[Dict[str, Any]] = field(default_factory=list)
    answer_types: List[str] = field(default_factory=list)
    answer_ttls: List[int] = field(default_factory=list)
    packet_size_bytes: int = 0
    dns_payload_bytes: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def safe_int(val: Any, default: int = 0) -> int:
    """Safely converts a value to int, defaulting to `default` if None or unparseable."""
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def extract_dns_records(section: Any, record_cls: type) -> List[Any]:
    """Safely extracts all record objects from a Scapy DNS section (list, tuple, or chained payload)."""
    records: List[Any] = []
    if section is None:
        return records
    items = section if isinstance(section, (list, tuple)) else [section]
    for item in items:
        curr = item
        seen = set()
        while curr and id(curr) not in seen:
            seen.add(id(curr))
            if isinstance(curr, record_cls):
                records.append(curr)
                curr = getattr(curr, "payload", None)
            else:
                break
    return records


class DNSParser:
    """
    Parser for decomposing network packets into normalized DNS records.
    """

    @staticmethod
    def is_dns_packet(packet: Packet) -> bool:
        """
        Quick check if packet contains a DNS layer over UDP or TCP.
        """
        return bool(packet.haslayer(DNS))

    @classmethod
    def parse_packet(cls, packet: Packet, frame_number: int = 0) -> Optional[ParsedDNSMessage]:
        """
        Parses a single Scapy packet.
        Returns a ParsedDNSMessage if the packet contains DNS traffic,
        or None if the packet is non-DNS.
        """
        if not cls.is_dns_packet(packet):
            return None

        try:
            timestamp = float(packet.time)
        except Exception:
            timestamp = 0.0

        timestamp_iso = format_timestamp(timestamp)

        # Extract Network / Transport Layer info
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_port = 0
        dst_port = 0
        ip_version: Optional[int] = None
        transport_protocol = "Unknown"

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            ip_version = 4
        elif packet.haslayer(IPv6):
            ipv6_layer = packet[IPv6]
            src_ip = str(ipv6_layer.src)
            dst_ip = str(ipv6_layer.dst)
            ip_version = 6

        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = safe_int(udp_layer.sport)
            dst_port = safe_int(udp_layer.dport)
            transport_protocol = "UDP"
        elif packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = safe_int(tcp_layer.sport)
            dst_port = safe_int(tcp_layer.dport)
            transport_protocol = "TCP"

        # Extract DNS Layer info
        dns_layer = packet[DNS]
        transaction_id = safe_int(getattr(dns_layer, "id", 0))
        qr_flag = safe_int(getattr(dns_layer, "qr", 0))
        is_response = (qr_flag == 1)
        opcode = safe_int(getattr(dns_layer, "opcode", 0))
        aa = safe_int(getattr(dns_layer, "aa", 0))
        tc = safe_int(getattr(dns_layer, "tc", 0))
        rd = safe_int(getattr(dns_layer, "rd", 0))
        ra = safe_int(getattr(dns_layer, "ra", 0))
        rcode = safe_int(getattr(dns_layer, "rcode", 0))
        rcode_name = get_rcode_name(rcode)

        # Safely extract section counts (may be None in Scapy before build)
        raw_qdcount = safe_int(getattr(dns_layer, "qdcount", None))
        raw_ancount = safe_int(getattr(dns_layer, "ancount", None))
        nscount = safe_int(getattr(dns_layer, "nscount", None))
        arcount = safe_int(getattr(dns_layer, "arcount", None))

        # Parse Questions (QD section)
        questions_list: List[Dict[str, Any]] = []
        primary_qname = ""
        primary_qtype = ""

        try:
            qd_records = extract_dns_records(getattr(dns_layer, "qd", None), DNSQR)
            for curr_qd in qd_records:
                raw_qname = getattr(curr_qd, "qname", None)
                norm_qname = normalize_domain(raw_qname)
                qtype_code = safe_int(getattr(curr_qd, "qtype", 0))
                qtype_name = get_record_type_name(qtype_code)
                qclass = safe_int(getattr(curr_qd, "qclass", 1), default=1)

                q_obj = DNSQuestion(
                    qname=norm_qname,
                    qtype=qtype_name,
                    qtype_code=qtype_code,
                    qclass=qclass
                )
                questions_list.append(q_obj.to_dict())

                if not primary_qname and norm_qname:
                    primary_qname = norm_qname
                    primary_qtype = qtype_name
        except Exception as e:
            logger.debug(f"Error parsing questions in frame {frame_number}: {e}")

        # Parse Answers (AN section)
        answers_list: List[Dict[str, Any]] = []
        answer_types: List[str] = []
        answer_ttls: List[int] = []

        try:
            an_records = extract_dns_records(getattr(dns_layer, "an", None), DNSRR)
            for curr_an in an_records:
                rr_raw = getattr(curr_an, "rrname", None)
                rrname = normalize_domain(rr_raw)
                type_code = safe_int(getattr(curr_an, "type", 0))
                type_name = get_record_type_name(type_code)
                ttl = safe_int(getattr(curr_an, "ttl", 0))

                rdata_raw = getattr(curr_an, "rdata", "")
                if isinstance(rdata_raw, bytes):
                    try:
                        rdata_str = rdata_raw.decode("utf-8", errors="replace")
                    except Exception:
                        rdata_str = str(rdata_raw)
                else:
                    rdata_str = str(rdata_raw)

                # Normalize domain in rdata if CNAME / PTR / NS
                if type_name in ("CNAME", "PTR", "NS"):
                    rdata_str = normalize_domain(rdata_str)

                ans_obj = DNSAnswer(
                    rrname=rrname,
                    type=type_name,
                    type_code=type_code,
                    rdata=rdata_str,
                    ttl=ttl
                )
                answers_list.append(ans_obj.to_dict())
                answer_types.append(type_name)
                answer_ttls.append(ttl)
        except Exception as e:
            logger.debug(f"Error parsing answers in frame {frame_number}: {e}")

        qdcount = len(questions_list) if raw_qdcount == 0 and questions_list else raw_qdcount
        ancount = len(answers_list) if raw_ancount == 0 and answers_list else raw_ancount

        # Determine sizes
        try:
            packet_size = len(packet)
        except Exception:
            packet_size = 0

        try:
            dns_size = len(dns_layer)
        except Exception:
            dns_size = 0

        # Unique answer types preserving order
        unique_answer_types = list(dict.fromkeys(answer_types))

        return ParsedDNSMessage(
            frame_number=frame_number,
            timestamp=timestamp,
            timestamp_iso=timestamp_iso,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            ip_version=ip_version,
            transport_protocol=transport_protocol,
            transaction_id=transaction_id,
            is_response=is_response,
            qr_flag=qr_flag,
            opcode=opcode,
            aa=aa,
            tc=tc,
            rd=rd,
            ra=ra,
            rcode=rcode,
            rcode_name=rcode_name,
            qdcount=qdcount,
            ancount=ancount,
            nscount=nscount,
            arcount=arcount,
            questions=questions_list,
            primary_qname=primary_qname,
            primary_qtype=primary_qtype,
            answers=answers_list,
            answer_types=unique_answer_types,
            answer_ttls=answer_ttls,
            packet_size_bytes=packet_size,
            dns_payload_bytes=dns_size,
            error=None
        )
