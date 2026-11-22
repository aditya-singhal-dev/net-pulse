"""Measure a TCP handshake separately from hostname resolution."""

import errno
import socket
from dataclasses import dataclass
from ipaddress import ip_address
from time import monotonic

from config.settings import validate_host
from core.dns_analyzer import lookup


@dataclass(frozen=True)
class TCPResult:
    host: str
    port: int
    status: str
    elapsed_ms: float | None = None
    address: str | None = None
    detail: str | None = None


def connect(host: str, port: int, timeout: float) -> TCPResult:
    host = validate_host(host)
    if not 1 <= port <= 65535:
        raise ValueError("TCP ports must be in 1–65535")
    deadline = monotonic() + timeout
    try:
        addresses = (str(ip_address(host)),)
    except ValueError:
        result = lookup(host, timeout)
        if result.status != "ok":
            return TCPResult(host, port, "dns_failure", detail=f"{result.status}: {result.detail}")
        addresses = result.addresses
    last_error = "No addresses available"
    status = "error"
    for address in addresses:
        remaining = deadline - monotonic()
        if remaining <= 0:
            return TCPResult(host, port, "timeout", detail="TCP probe deadline expired")
        family = socket.AF_INET6 if ip_address(address).version == 6 else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(remaining)
                start = monotonic()
                client.connect((address, port))
                return TCPResult(host, port, "ok", (monotonic() - start) * 1000, address)
        except TimeoutError as exc:
            status, last_error = "timeout", str(exc)
        except ConnectionRefusedError as exc:
            status, last_error = "refused", str(exc)
        except OSError as exc:
            status = "unreachable" if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH) else "error"
            last_error = str(exc)
    return TCPResult(host, port, status, detail=last_error)
