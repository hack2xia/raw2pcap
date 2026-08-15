"""raw2pcap - create pcap files from raw HTTP request/response text."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version

try:
    __version__ = _dist_version("raw2pcap")
except PackageNotFoundError:  # running from a source checkout without install
    __version__ = "0.1.1"

from raw2pcap.generate import generate_pcap

__all__ = ["__version__", "generate_pcap"]
