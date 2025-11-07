"""
PCAP Parser for extracting HTTP requests from network traffic.
Supports both PCAP and PCAPNG formats.
"""
from typing import List, Dict, Optional, Generator
import logging
from urllib.parse import unquote
from datetime import datetime

try:
    from scapy.all import rdpcap, TCP, IP, Raw
    from scapy.layers.http import HTTPRequest, HTTP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not installed. PCAP parsing will not be available.")

logger = logging.getLogger(__name__)


class HTTPRequestData:
    """Data class for HTTP request information"""

    def __init__(
        self,
        timestamp: datetime,
        source_ip: str,
        dest_ip: str,
        source_port: int,
        dest_port: int,
        method: str,
        url: str,
        host: str,
        user_agent: Optional[str] = None,
        referer: Optional[str] = None,
        raw_request: Optional[str] = None,
    ):
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.method = method
        self.url = url
        self.host = host
        self.user_agent = user_agent
        self.referer = referer
        self.raw_request = raw_request

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "user_agent": self.user_agent,
            "referer": self.referer,
            "raw_request": self.raw_request,
        }

    def get_full_url(self) -> str:
        """Get the full URL including host"""
        if self.url.startswith("http"):
            return self.url
        return f"http://{self.host}{self.url}" if self.host else self.url


class PCAPParser:
    """Parser for PCAP files to extract HTTP requests"""

    def __init__(self):
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy is required for PCAP parsing. Install with: pip install scapy")

    def parse_pcap(self, pcap_path: str, max_packets: Optional[int] = None) -> List[HTTPRequestData]:
        """
        Parse PCAP file and extract HTTP requests.

        Args:
            pcap_path: Path to PCAP file
            max_packets: Maximum number of packets to process (None for all)

        Returns:
            List of HTTPRequestData objects
        """
        logger.info(f"Parsing PCAP file: {pcap_path}")
        requests = []

        try:
            packets = rdpcap(pcap_path)
            logger.info(f"Loaded {len(packets)} packets from PCAP")

            count = 0
            for packet in packets:
                if max_packets and count >= max_packets:
                    break

                request_data = self._extract_http_request(packet)
                if request_data:
                    requests.append(request_data)
                    count += 1

            logger.info(f"Extracted {len(requests)} HTTP requests")
            return requests

        except Exception as e:
            logger.error(f"Error parsing PCAP file: {e}")
            raise

    def parse_pcap_stream(
        self, pcap_path: str, chunk_size: int = 1000
    ) -> Generator[List[HTTPRequestData], None, None]:
        """
        Stream parse PCAP file in chunks for memory efficiency.

        Args:
            pcap_path: Path to PCAP file
            chunk_size: Number of requests per chunk

        Yields:
            Lists of HTTPRequestData objects
        """
        logger.info(f"Stream parsing PCAP file: {pcap_path}")

        try:
            packets = rdpcap(pcap_path)
            chunk = []

            for packet in packets:
                request_data = self._extract_http_request(packet)
                if request_data:
                    chunk.append(request_data)

                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []

            # Yield remaining requests
            if chunk:
                yield chunk

        except Exception as e:
            logger.error(f"Error stream parsing PCAP file: {e}")
            raise

    def _extract_http_request(self, packet) -> Optional[HTTPRequestData]:
        """
        Extract HTTP request data from a packet.

        Args:
            packet: Scapy packet object

        Returns:
            HTTPRequestData object or None
        """
        try:
            # Check if packet has HTTP layer
            if packet.haslayer(HTTPRequest):
                return self._parse_http_request_layer(packet)

            # Fallback: Try to parse raw TCP data
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                return self._parse_raw_http(packet)

            return None

        except Exception as e:
            logger.debug(f"Error extracting HTTP request: {e}")
            return None

    def _parse_http_request_layer(self, packet) -> Optional[HTTPRequestData]:
        """Parse packet with HTTP request layer"""
        try:
            http_layer = packet[HTTPRequest]

            # Extract basic info
            method = http_layer.Method.decode() if http_layer.Method else "GET"
            path = http_layer.Path.decode() if http_layer.Path else "/"
            host = http_layer.Host.decode() if http_layer.Host else ""

            # Extract headers
            user_agent = None
            referer = None

            if hasattr(http_layer, 'User_Agent') and http_layer.User_Agent:
                user_agent = http_layer.User_Agent.decode()

            if hasattr(http_layer, 'Referer') and http_layer.Referer:
                referer = http_layer.Referer.decode()

            # Extract IP info
            source_ip = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"
            dest_ip = packet[IP].dst if packet.haslayer(IP) else "0.0.0.0"
            source_port = packet[TCP].sport if packet.haslayer(TCP) else 0
            dest_port = packet[TCP].dport if packet.haslayer(TCP) else 80

            # Get timestamp
            timestamp = datetime.fromtimestamp(float(packet.time))

            # Get raw request
            raw_request = bytes(packet[HTTPRequest]).decode('utf-8', errors='ignore')

            # Decode URL
            url = unquote(path)

            return HTTPRequestData(
                timestamp=timestamp,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                method=method,
                url=url,
                host=host,
                user_agent=user_agent,
                referer=referer,
                raw_request=raw_request,
            )

        except Exception as e:
            logger.debug(f"Error parsing HTTP request layer: {e}")
            return None

    def _parse_raw_http(self, packet) -> Optional[HTTPRequestData]:
        """Parse raw TCP packet that might contain HTTP request"""
        try:
            if not packet.haslayer(TCP) or not packet.haslayer(Raw):
                return None

            payload = packet[Raw].load

            # Try to decode as HTTP request
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
            except:
                return None

            # Check if it looks like an HTTP request
            lines = payload_str.split('\r\n')
            if not lines or not lines[0]:
                return None

            request_line = lines[0].split()
            if len(request_line) < 3:
                return None

            method = request_line[0]
            path = request_line[1]
            http_version = request_line[2]

            # Must be HTTP
            if not http_version.startswith('HTTP/'):
                return None

            # Extract headers
            host = ""
            user_agent = None
            referer = None

            for line in lines[1:]:
                if ':' not in line:
                    continue

                header, value = line.split(':', 1)
                header = header.strip().lower()
                value = value.strip()

                if header == 'host':
                    host = value
                elif header == 'user-agent':
                    user_agent = value
                elif header == 'referer':
                    referer = value

            # Extract IP info
            source_ip = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"
            dest_ip = packet[IP].dst if packet.haslayer(IP) else "0.0.0.0"
            source_port = packet[TCP].sport
            dest_port = packet[TCP].dport

            # Get timestamp
            timestamp = datetime.fromtimestamp(float(packet.time))

            # Decode URL
            url = unquote(path)

            return HTTPRequestData(
                timestamp=timestamp,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                method=method,
                url=url,
                host=host,
                user_agent=user_agent,
                referer=referer,
                raw_request=payload_str[:1000],  # First 1000 chars
            )

        except Exception as e:
            logger.debug(f"Error parsing raw HTTP: {e}")
            return None


def parse_pcap_file(pcap_path: str, max_requests: Optional[int] = None) -> List[HTTPRequestData]:
    """
    Convenience function to parse PCAP file.

    Args:
        pcap_path: Path to PCAP file
        max_requests: Maximum number of requests to extract

    Returns:
        List of HTTPRequestData objects
    """
    parser = PCAPParser()
    return parser.parse_pcap(pcap_path, max_packets=max_requests)
