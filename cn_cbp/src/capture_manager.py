"""
Capture Manager module.
Handles loading, validation, and packet extraction from .pcap and .pcapng capture files,
providing progress tracking and graceful error handling for corrupted captures.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, Dict, List, Optional, Tuple, Union

from scapy.utils import PcapReader, rdpcap

from src.dns_parser import DNSParser, ParsedDNSMessage
from src.utils import format_timestamp

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@dataclass
class CaptureMetadata:
    """Metadata regarding the loaded capture file."""
    filename: str
    filepath: Optional[str]
    file_size_bytes: int
    total_packets: int
    dns_packets: int
    non_dns_packets: int
    parse_errors: int
    first_packet_time: Optional[float]
    last_packet_time: Optional[float]
    duration_seconds: float
    start_time_iso: str
    end_time_iso: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CaptureLoadingError(Exception):
    """Raised when a capture file cannot be loaded or is invalid."""
    pass


class CaptureManager:
    """
    Manages loading, validation, and reading of PCAP/PCAPNG capture files.
    """

    @staticmethod
    def validate_capture_path(file_path: Union[str, Path]) -> Path:
        """
        Validates that the file exists, is non-empty, and has a supported extension.
        """
        path = Path(file_path)
        if not path.exists():
            raise CaptureLoadingError(f"File not found: {path}")

        if not path.is_file():
            raise CaptureLoadingError(f"Path is not a regular file: {path}")

        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            raise CaptureLoadingError(
                f"Unsupported file format '{path.suffix}'. Supported formats are: "
                f"{', '.join(sorted(SUPPORTED_EXTENSIONS))}"
            )

        file_size = path.stat().st_size
        if file_size == 0:
            raise CaptureLoadingError(f"Capture file is empty (0 bytes): {path.name}")

        return path

    @classmethod
    def load_from_path(
        cls,
        file_path: Union[str, Path],
        progress_callback: Optional[Callable[[int, int], None]] = None,
        max_packets: Optional[int] = None
    ) -> Tuple[CaptureMetadata, List[ParsedDNSMessage]]:
        """
        Loads packets from a local PCAP/PCAPNG file.
        Returns capture metadata and the list of successfully parsed DNS messages.
        """
        path = cls.validate_capture_path(file_path)
        file_size = path.stat().st_size
        filename = path.name

        dns_messages: List[ParsedDNSMessage] = []
        total_packets = 0
        dns_packets = 0
        non_dns_packets = 0
        parse_errors = 0
        first_time: Optional[float] = None
        last_time: Optional[float] = None

        try:
            with PcapReader(str(path)) as reader:
                frame_number = 0
                for pkt in reader:
                    frame_number += 1
                    total_packets += 1

                    try:
                        pkt_time = float(pkt.time)
                        if first_time is None or pkt_time < first_time:
                            first_time = pkt_time
                        if last_time is None or pkt_time > last_time:
                            last_time = pkt_time
                    except Exception:
                        pass

                    if DNSParser.is_dns_packet(pkt):
                        try:
                            dns_msg = DNSParser.parse_packet(pkt, frame_number=frame_number)
                            if dns_msg:
                                dns_messages.append(dns_msg)
                                dns_packets += 1
                            else:
                                non_dns_packets += 1
                        except Exception as e:
                            parse_errors += 1
                            logger.warning(f"Error parsing DNS frame #{frame_number}: {e}")
                    else:
                        non_dns_packets += 1

                    if progress_callback and frame_number % 250 == 0:
                        progress_callback(frame_number, total_packets)

                    if max_packets and total_packets >= max_packets:
                        logger.info(f"Reached max_packets threshold ({max_packets})")
                        break

        except Exception as e:
            # If PcapReader failed, try fallback rdpcap
            if total_packets == 0:
                try:
                    logger.info("PcapReader encountered an issue, trying rdpcap fallback...")
                    packets = rdpcap(str(path))
                    frame_number = 0
                    for pkt in packets:
                        frame_number += 1
                        total_packets += 1
                        try:
                            pkt_time = float(pkt.time)
                            if first_time is None or pkt_time < first_time:
                                first_time = pkt_time
                            if last_time is None or pkt_time > last_time:
                                last_time = pkt_time
                        except Exception:
                            pass

                        if DNSParser.is_dns_packet(pkt):
                            try:
                                dns_msg = DNSParser.parse_packet(pkt, frame_number=frame_number)
                                if dns_msg:
                                    dns_messages.append(dns_msg)
                                    dns_packets += 1
                                else:
                                    non_dns_packets += 1
                            except Exception as pe:
                                parse_errors += 1
                        else:
                            non_dns_packets += 1
                except Exception as fallback_err:
                    raise CaptureLoadingError(
                        f"Failed to read capture file '{filename}': {fallback_err}"
                    ) from fallback_err
            else:
                logger.warning(f"Capture reading ended prematurely after {total_packets} packets: {e}")

        duration = 0.0
        if first_time is not None and last_time is not None:
            duration = max(0.0, last_time - first_time)

        metadata = CaptureMetadata(
            filename=filename,
            filepath=str(path.resolve()),
            file_size_bytes=file_size,
            total_packets=total_packets,
            dns_packets=dns_packets,
            non_dns_packets=non_dns_packets,
            parse_errors=parse_errors,
            first_packet_time=first_time,
            last_packet_time=last_time,
            duration_seconds=duration,
            start_time_iso=format_timestamp(first_time),
            end_time_iso=format_timestamp(last_time)
        )

        return metadata, dns_messages

    @classmethod
    def load_from_buffer(
        cls,
        buffer: BinaryIO,
        filename: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Tuple[CaptureMetadata, List[ParsedDNSMessage]]:
        """
        Saves an uploaded in-memory buffer to a temporary file and loads it.
        Ensures proper cleanup after processing.
        """
        suffix = Path(filename).suffix.lower()
        if suffix not in SUPPORTED_EXTENSIONS:
            suffix = ".pcapng"

        # Create a temp file to store buffer contents
        temp_dir = Path("outputs") / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        temp_file_path = temp_dir / f"upload_{os.getpid()}_{Path(filename).name}"
        try:
            buffer.seek(0)
            with open(temp_file_path, "wb") as f_out:
                shutil.copyfileobj(buffer, f_out)

            metadata, messages = cls.load_from_path(temp_file_path, progress_callback=progress_callback)
            metadata.filename = filename  # retain original filename
            return metadata, messages
        finally:
            if temp_file_path.exists():
                try:
                    temp_file_path.unlink()
                except Exception as e:
                    logger.debug(f"Could not remove temp file {temp_file_path}: {e}")
