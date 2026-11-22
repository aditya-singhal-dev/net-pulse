"""Time A and AAAA lookups through the configured DNS resolver."""

from dataclasses import dataclass
from time import perf_counter

import dns.exception
import dns.resolver

from config.settings import validate_host


@dataclass(frozen=True)
class DNSResult:
    domain: str
    status: str
    elapsed_ms: float | None = None
    addresses: tuple[str, ...] = ()
    detail: str | None = None


def lookup(domain: str, timeout: float) -> DNSResult:
    domain = validate_host(domain)
    try:
        resolver = dns.resolver.Resolver()
        start = perf_counter()
        answer = resolver.resolve_name(domain, lifetime=timeout)
        elapsed_ms = (perf_counter() - start) * 1000
        return DNSResult(domain, "ok", elapsed_ms, tuple(answer.addresses()))
    except dns.resolver.NXDOMAIN as exc:
        return DNSResult(domain, "nxdomain", detail=str(exc))
    except dns.resolver.NoAnswer as exc:
        return DNSResult(domain, "no_answer", detail=str(exc))
    except dns.exception.Timeout as exc:
        return DNSResult(domain, "timeout", detail=str(exc))
    except (dns.exception.DNSException, OSError) as exc:
        return DNSResult(domain, "error", detail=str(exc))
