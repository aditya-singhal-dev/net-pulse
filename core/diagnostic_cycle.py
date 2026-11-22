"""Collect a single bounded set of measurements."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from time import sleep

from config.settings import Settings
from core import bandwidth_monitor, dns_analyzer, ping_monitor, tcp_checker
from core.network_info import NetworkInfo, get_network_info


@dataclass(frozen=True)
class DiagnosticCycle:
    timestamp: str
    network: NetworkInfo
    bandwidth: bandwidth_monitor.Bandwidth
    ping: tuple[ping_monitor.PingResult, ...]
    dns: tuple[dns_analyzer.DNSResult, ...]
    tcp: tuple[tcp_checker.TCPResult, ...]

    @property
    def status(self) -> str:
        if any(probe.status == "ok" for probe in self.tcp):
            return "tcp_reachable"
        return "inconclusive"


def collect(settings: Settings) -> DiagnosticCycle:
    timestamp = datetime.now(timezone.utc).isoformat()
    network = get_network_info()
    first = bandwidth_monitor.sample(network.interface)
    with ThreadPoolExecutor(max_workers=6) as executor:
        ping_jobs = [
            executor.submit(ping_monitor.ping, host, settings.ping_count, settings.timeout)
            for host in settings.ping_targets
        ]
        dns_jobs = [
            executor.submit(dns_analyzer.lookup, host, settings.timeout)
            for host in settings.dns_domains
        ]
        tcp_jobs = [
            executor.submit(tcp_checker.connect, host, port, settings.timeout)
            for host, port in settings.tcp_endpoints
        ]
        if first is not None:
            sleep(1)
        bandwidth = bandwidth_monitor.calculate(first, bandwidth_monitor.sample(network.interface))
        return DiagnosticCycle(
            timestamp, network, bandwidth, tuple(job.result() for job in ping_jobs),
            tuple(job.result() for job in dns_jobs), tuple(job.result() for job in tcp_jobs),
        )
