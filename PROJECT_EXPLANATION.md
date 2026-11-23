# NetPulse project explanation

## Abstract

NetPulse is a macOS application that measures network conditions, records the results, and suggests troubleshooting steps. It combines ICMP, DNS, TCP, routing information, and interface counters. A Streamlit dashboard displays current and historical measurements, while a rule-based engine explains observed symptoms and attaches plausible causes. Results are stored in SQLite and can be exported as CSV or printable HTML.

## Problem statement

A user experiencing slow or unreliable internet access often has only a general impression that the connection is poor. A working Wi-Fi link does not establish that DNS or a remote TCP service works. An unanswered ping also has several possible explanations. NetPulse collects evidence across protocols so the user can choose a more specific next troubleshooting step.

## Objectives

- Measure RTT, packet loss, jitter, DNS lookup time, TCP handshake time, and local traffic rates.
- Discover the default route, active interface, gateway, and local addresses.
- Track measurements over time and summarize health with a documented 0–100 heuristic.
- Produce evidence-based findings, downloadable reports, and optional path and packet views.

## Methodology

1. Read interface addresses and cumulative byte counters through macOS and psutil.
2. Run bounded ICMP echo probes, DNS lookups, and TCP connections in parallel. Measure local traffic rates over a short interval using a monotonic clock.
3. Score the usable measurements. Evaluate rules for high latency, jitter, loss, slow or failed DNS, failed TCP connections, interface disconnects, and sudden changes in local traffic.
4. Commit each cycle, its probes, and its assessment together in SQLite. The monitoring worker waits between cycles while Streamlit reads saved data.
5. Chart trends, inspect target-level outcomes, or export a UTC date range to CSV or HTML. Traceroute and packet inspection run as separate optional diagnostics.

## Expected results

A working network produces measured timings, traffic counters, and probe statuses. A degraded network may show an increase in latency, packet loss, or DNS time, alongside findings and practical next steps. With too little usable evidence the score is unavailable and the diagnosis can be inconclusive. The offline demo provides a repeatable example of worsening measurements with clearly labeled synthetic data.

## Computer Networks syllabus mapping

| Topic | NetPulse example |
| --- | --- |
| Network layer and IP addressing | Display of local IPv4 and IPv6 addresses, interface, gateway, and numeric traceroute hops. |
| ICMP and diagnostics | Echo request/reply timing and loss. Traceroute interprets hop-limit replies where routers send them. |
| Routing, TTL, and hop limit | A default route determines the outgoing interface. Traceroute increases the TTL or IPv6 hop limit to reveal responding routers. |
| Transport layer and TCP | Socket connections measure the time to establish a TCP connection. |
| UDP and application-layer DNS | DNS usually starts over UDP and can fall back to TCP. UDP traceroute sends one probe per hop. |
| Performance and quality of service | RTT, loss, jitter, and interface throughput are measured and shown over time. |
| Network management | Configurable thresholds, historical dashboards, reports, and optional packet metadata inspection. |

## Viva questions and answers

**1. What is RTT?**  
Round-trip time is the elapsed time between sending a probe and receiving its reply. It includes both directions and can include queueing and endpoint processing.

**2. How does NetPulse calculate packet loss?**  
It divides the number of ICMP probes without replies by the number transmitted, then multiplies by 100. If the command cannot measure transmitted probes, loss is unavailable.

**3. How does this project define jitter?**  
It averages the absolute differences between consecutive successful RTT samples. Two successful replies are required for one difference.

**4. Can a site work even when ping fails?**  
Yes. A router or a destination may filter or rate-limit ICMP echo while DNS or TCP still works. Compare multiple probes before inferring an outage.

**5. Why measure DNS and TCP separately?**  
DNS maps a name to an address. TCP then tries to establish a connection to an address and port. Timing the two separately helps locate which stage was slow or failed.

**6. What does the TCP timing measure?**  
It measures successful socket connection establishment. TLS negotiation, HTTP response time, and page rendering occur after that TCP test finishes.

**7. How does traceroute discover intermediate routers?**  
It sends probes with increasing TTL or IPv6 hop limit. A router that drops a probe after decrementing the limit may reply with ICMP Time Exceeded, revealing its address.

**8. How are the Mbps values calculated?**  
NetPulse subtracts two cumulative byte readings for the same interface, multiplies the byte difference by eight, and divides by the actual elapsed seconds and one million.

**9. Why does the health score sometimes disappear?**  
The heuristic needs at least 35 percentage points of measurable weight and evidence from two of ICMP, DNS, and TCP. Unavailable measurements are excluded. An explicit failed probe can still contribute a penalty where the scoring rules define one.

**10. How does the app avoid duplicate monitoring threads?**  
Streamlit caches one monitoring service per database path in the server process. The service uses a lock to reserve its worker slot and an event to signal stop. The UI reads committed SQLite results independently.

**11. How can packet analysis work without administrator access?**  
A user can import an existing PCAP or PCAPNG file. Live capture additionally requires authorization and macOS BPF permissions on the chosen interface. The live feature limits collection to base IP headers and displays protocol counts and address pairs.

**12. What would you demonstrate in three minutes?**  
Run one cycle from Overview, explain its probe results, start and stop Live Monitoring, open a finding on the Diagnostics page, and generate both export formats. To demonstrate a repeatable degraded case without network access, launch the labeled offline demo.
