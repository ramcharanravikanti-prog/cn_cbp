# DNS Traffic Analysis Using Wireshark — How to Explain It to Your Teacher

This guide is your script: what the project does, what each tab shows, every field with its
full form, and the real results from `captures/my_capture.pcapng`.

---

## 1. The 30-second pitch

> "Wireshark can capture DNS packets, but it cannot answer questions like *how many unique
> domains were queried, what was the average response time, how many lookups failed, or which
> queries never got a reply*. My project reads the `.pcapng` file Wireshark produces, parses
> every DNS packet field-by-field according to RFC 1035, pairs each query with its response
> using the 5-tuple socket and transaction ID, computes latency in milliseconds, and shows
> everything in an interactive Streamlit dashboard with charts and CSV/JSON/report exports.
> It analyses 1,761 real packets from my own machine end to end."

**One-line architecture:**

`pcapng → CaptureManager (Scapy) → DNSParser → QueryCorrelator → DNSStatistics → Charts + Reports + Streamlit UI`

---

## 2. How the code is organised (say this if asked "what did you build?")

| File | Full form / role | What it does |
| :--- | :--- | :--- |
| `app.py` | Application entry point | Streamlit dashboard: sidebar controls, 6 tabs, KPI cards, charts |
| `src/capture_manager.py` | Capture Manager | Opens `.pcap`/`.pcapng` with Scapy `PcapReader`, counts packets, extracts timestamps |
| `src/dns_parser.py` | DNS Parser | Dissects each DNS packet into a `ParsedDNSMessage` (every header flag + questions + answers) |
| `src/query_correlator.py` | Query Correlator | Pairs queries with responses using 5-tuple + transaction ID + time causality |
| `src/statistics.py` | Statistics Engine | Latency stats (mean/median/p95), domain frequency, query-type and RCODE distributions |
| `src/visualizations.py` | Visualization module | Six publication-quality Matplotlib charts in a dark theme |
| `src/report_generator.py` | Report Generator | Writes 7 CSVs, a JSON summary and a Markdown report |
| `src/utils.py` | Utilities | Domain normalisation (lowercase, strip trailing dot) + DNS lookup tables |
| `scripts/generate_test_capture.py` | Test data generator | Builds a synthetic 20-packet capture with Scapy for testing (not real traffic) |
| `scripts/validate_capture.py` | CLI validator | Prints a text summary of any capture without opening the dashboard |
| `tests/` | Unit tests | 20 pytest tests for parsing, correlation, statistics and export |

**Two important design points to defend:**

1. **Correlation is not just "same transaction ID".** A 16-bit ID has only 65,536 values and gets
   reused, so the tool matches on the inverted 5-tuple:
   `(transaction_id, client_ip, server_ip, client_port, server_port, protocol)`, requires the
   names to match, and enforces `T_response ≥ T_query` within a 30-second window. That is why the
   negative-latency test passes.
2. **Nothing is fabricated.** Unanswered queries are reported as *unmatched*, not as failures,
   because a response can simply fall outside the capture window or be answered from cache.

---

## 3. The demo order (click these in this order)

1. Sidebar → **Select Existing Capture** → `my_capture.pcapng` → **🚀 Analyze Capture**.
2. **Overview** → read the 8 KPI cards, then the narrative paragraph.
3. **DNS Traffic Explorer** → filter Domain Search = `microsoft`, show the table.
4. **Visual Analytics** → scroll through the six charts.
5. **Packet Details** → pick one slow transaction, show the flags and the correlation box.
6. **Findings & Report** → move the slow-query slider, then the download buttons.
7. **Capture Guide & Setup** → proves the Wireshark workflow is documented.

---

## 4. What each tab shows (and what to say)

### Sidebar — 📁 Capture Selection
Choose a capture already in `captures/` **or** upload one. Because analysis is done on the
server side, the dashboard accepts both `.pcap` and `.pcapng`.

**Say:** "There are two input paths: a local file for offline use, and an upload for convenience.
Both go through the same parser, so the numbers are identical."

### Sidebar — 🔍 Filter Controls
- **Message Direction:** All / Queries Only / Responses Only
- **Domain Search:** substring match on the queried name *and* on answer rdata
- **Query Types:** A, AAAA, MX, TXT, PTR, HTTPS…
- **Response Codes:** NOERROR, NXDOMAIN, SERVFAIL…
- **Transport Protocols:** UDP / TCP

**Say:** "Filters re-run on the already-parsed in-memory list, so they are instant — no re-reading
of the capture. The Overview KPIs always reflect the whole capture; the Explorer and charts follow
the filters."

### Tab 1 — 📊 Overview
Eight KPI cards plus a written narrative and file metadata:

| Card | What it counts |
| :--- | :--- |
| Total Packets | Every frame in the file (DNS + non-DNS) |
| DNS Packets | Frames containing a DNS layer |
| DNS Queries | Messages with QR = 0 |
| DNS Responses | Messages with QR = 1 |
| Unique Domains | Distinct normalised names queried |
| Matched Transactions | Query–response pairs successfully correlated |
| Mean Latency | Average `T_response − T_query` in ms (median shown underneath) |
| NXDOMAIN Responses | Responses with RCODE = 3 |

Below that: capture duration, start/end time in UTC, unanswered queries and unmatched responses.

**Say:** "These are the executive numbers. Note that DNS packets is smaller than total packets —
the rest is HTTPS/TCP/ARP traffic that Wireshark captured but my parser correctly ignores."

### Tab 2 — 🔎 DNS Traffic Explorer
A paginated table of every DNS message (25/50/100/250 rows per page) with these columns:

| Column | Meaning |
| :--- | :--- |
| Frame | Packet number as Wireshark numbers it |
| Timestamp | Captured time in UTC, millisecond precision |
| Direction | Query or Response (from the QR flag) |
| Source | `ip:port` of the sender |
| Destination | `ip:port` of the receiver |
| Protocol | UDP or TCP |
| Tx ID | 16-bit transaction identifier in hex (`0x52a4`) |
| Domain | Queried name, normalised |
| Type | Requested record type (A, AAAA, PTR, …) |
| RCODE | Response code name, `-` for queries |
| Answers Count | Number of resource records in the answer section |

**Say:** "This is the searchable replacement for Wireshark's packet list, but already parsed —
each row is one DNS message with the fields that matter, and the caption shows how many rows
match the active filters."

### Tab 3 — 📈 Visual Analytics
Six charts, each with an interpretation caption underneath:

1. **Top 10 Queried Domains** (horizontal bar) — counted from *queries only*, so responses cannot
   inflate the ranking.
2. **DNS Query Record-Type Distribution** (bar) — which record types clients asked for.
3. **DNS Response-Code Distribution** (bar) — NOERROR green, NXDOMAIN amber, other errors red.
4. **Query-Response Latency Distribution** (histogram) — with median (dashed) and p95 (dotted)
   reference lines.
5. **DNS Query Volume Over Time** (line, auto-binned) — shows bursts and idle gaps.
6. **Transaction Outcomes Breakdown** (donut) — matched NOERROR vs matched NXDOMAIN vs unanswered
   queries vs unmatched responses.

**Say:** "Every chart has an empty state, so a capture with no DNS still renders without crashing —
that is tested. The latency histogram is the important one: the mean is pulled right by a few slow
lookups, which is why I also report the median and the 95th percentile."

### Tab 4 — 🔬 Packet Details
Deep inspection of a single selected frame:

- **Network & Addressing:** source/destination `ip:port`, IP version, transport, frame size,
  DNS payload size.
- **DNS Header Flags:** transaction ID (hex + decimal), QR, OpCode, AA, TC, RD, RA, RCODE.
- **Questions section** and **Answers section** as tables (name, type, class/TTL, rdata).
- **Query-Response Correlation:** either the matched frame numbers with the measured latency, or
  an explicit "no matching response in this capture window" / "no preceding query".

**Say:** "This is the packet-level proof: the same frame Wireshark shows, but with the correlation
result attached — which Wireshark does not compute."

### Tab 5 — 📋 Findings & Report
- A **slow-query threshold slider** (20–500 ms, default 100 ms) that counts transactions above it
  and explicitly warns that high latency is *not* evidence of an attack.
- **Download Project Report (.md)**, **Download JSON Summary**, and **💾 Export All 7 CSVs**.
- An in-app reader showing the generated Markdown report with tables of the real results.

**Say:** "The exports are generated from the analysed data, not hard-coded — the same capture
always produces the same files, which makes the results reproducible."

### Tab 6 — 📖 Capture Guide & Setup
Step-by-step: Wireshark interface selection, `dns` display filter, `nslookup` commands,
`ipconfig /flushdns`, saving as `.pcapng` into `captures/`, plus the PowerShell environment setup.

**Say:** "This documents how the capture was produced, so the experiment is repeatable by anyone."

---

## 5. Full field dictionary (full forms + definitions)

### 5.1 DNS message header (RFC 1035) — 12 bytes

| Field | Full form | Bits | Meaning |
| :--- | :--- | :--- | :--- |
| **ID** | Identifier / Transaction ID | 16 | Random value the client sets; the response must echo it. Only 65,536 values, so it can collide. |
| **QR** | Query/Response flag | 1 | `0` = query, `1` = response. Decides which side of the conversation a packet is. |
| **OpCode** | Operation Code | 4 | `0` QUERY (standard), `1` IQUERY (inverse), `2` STATUS, `4` NOTIFY, `5` UPDATE. |
| **AA** | Authoritative Answer | 1 | Set by the name server that owns the zone; means the answer is not from cache. |
| **TC** | TrunCation | 1 | Message was cut off to fit the transport limit; client should retry over TCP. |
| **RD** | Recursion Desired | 1 | Client asks the resolver to chase the answer on its behalf (almost always 1). |
| **RA** | Recursion Available | 1 | Resolver confirms it supports recursion. |
| **Z** | Reserved | 3 | Must be zero (one bit is now the AD/DNSSEC-authenticated bit). |
| **RCODE** | Response Code | 4 | Outcome: 0 NOERROR, 1 FORMERR, 2 SERVFAIL, 3 NXDOMAIN, 4 NOTIMP, 5 REFUSED. |
| **QDCOUNT** | Question Count | 16 | Number of entries in the question section (normally 1). |
| **ANCOUNT** | Answer Count | 16 | Number of resource records in the answer section. |
| **NSCOUNT** | Authority Count | 16 | Number of name-server (authority) records. |
| **ARCOUNT** | Additional Count | 16 | Number of additional records (e.g. OPT for EDNS0). |

### 5.2 Resource record fields

| Field | Full form | Meaning |
| :--- | :--- | :--- |
| **NAME / rrname** | Resource record owner name | The domain the record belongs to (may be a CNAME target). |
| **TYPE** | Record type | Numeric code (1 = A, 28 = AAAA, 5 = CNAME, …). |
| **CLASS** | Class | Usually `IN` (Internet, value 1). |
| **TTL** | Time To Live | Seconds a resolver/cache may keep the record. |
| **RDLENGTH** | RDATA length | Size of the data field in bytes. |
| **RDATA** | Record data | The payload: IPv4 address, IPv6 address, target name, text, etc. |

### 5.3 Record types you will see

| Type | Code | Full form / purpose |
| :--- | :--- | :--- |
| **A** | 1 | Address record — maps a name to an IPv4 address. |
| **AAAA** | 28 | Quad-A record — maps a name to an IPv6 address. |
| **CNAME** | 5 | Canonical Name — an alias pointing to another name (very common with CDNs). |
| **MX** | 15 | Mail eXchange — mail server host + priority. |
| **TXT** | 16 | Text record — SPF/DKIM/DMARC and domain verification strings. |
| **PTR** | 12 | Pointer — reverse lookup (`1.1.168.192.in-addr.arpa` → hostname). |
| **NS** | 2 | Name Server — which servers are authoritative for the zone. |
| **SOA** | 6 | Start Of Authority — zone metadata (serial, refresh, retry, expiry). |
| **SRV** | 33 | SeRVice locator — host + port for a service. |
| **HTTPS / SVCB** | 65 / 64 | Service binding hints (ALPN, port, IP hints) used by modern browsers. |
| **OPT** | 41 | EDNS0 pseudo-record — advertises UDP payload size and options. |
| **DS / DNSKEY / RRSIG** | 43 / 48 / 46 | DNSSEC delegation signer, public key and signature records. |
| **ANY** | 255 | Request for all available records (rarely honoured today). |

### 5.4 Response codes (RCODE)

| Code | Name | Full form | Meaning |
| :--- | :--- | :--- | :--- |
| 0 | NOERROR | No Error | Query completed successfully. |
| 1 | FORMERR | Format Error | Server could not interpret the query. |
| 2 | SERVFAIL | Server Failure | Resolver could not complete resolution (timeout, DNSSEC failure). |
| 3 | NXDOMAIN | Non-Existent Domain | The name does not exist in the zone. |
| 4 | NOTIMP | Not Implemented | Requested operation is unsupported. |
| 5 | REFUSED | Query Refused | Policy refusal (e.g. recursion disallowed). |
| 9 | NOTAUTH | Not Authoritative | Server is not authoritative for that zone. |

### 5.5 Transport and ports

| Term | Full form | Meaning |
| :--- | :--- | :--- |
| **UDP 53** | User Datagram Protocol, port 53 | Default DNS: connectionless, one packet each way. |
| **TCP 53** | Transmission Control Protocol, port 53 | Used for large responses, truncation retries and zone transfers; 2-byte length prefix. |
| **mDNS 5353** | Multicast DNS | Local discovery (`.local`), sent to `224.0.0.251` / `ff02::fb`; multiple devices may answer. |
| **DoH** | DNS over HTTPS | Encrypted DNS inside HTTPS (port 443) — cannot be parsed without TLS keys. |
| **DoT** | DNS over TLS | Encrypted DNS on port 853 — same limitation. |
| **5-tuple** | (src IP, src port, dst IP, dst port, protocol) | Identifies one socket conversation; a response has it reversed. |

### 5.6 Derived fields computed by this project

| Term | Definition |
| :--- | :--- |
| **Matched transaction** | A query and response paired by transaction ID + inverted 5-tuple + matching name + `T_response ≥ T_query`. |
| **Latency (ms)** | `(T_response − T_query) × 1000`. Includes client stack, network and resolver time. |
| **Mean / Median** | Arithmetic average / 50th percentile of latencies. Median is resistant to outliers. |
| **p95** | 95th percentile — 95% of lookups were faster than this value (`numpy.percentile`). |
| **Std dev** | Spread of latencies around the mean (sample of matched transactions). |
| **Unanswered query** | Query with no matching response inside the capture window (not automatically an error). |
| **Unmatched response** | Response with no preceding query in the capture (window boundary or a query missed). |
| **Retransmission** | An identical query (same 5-tuple, ID and name) sent again before the answer arrived. |
| **Unique domains** | Number of distinct normalised names in the query set. |
| **Percentage** | `count / total × 100`, rounded to 2 decimals, within its own distribution. |

### 5.7 Export files

| File | Contents |
| :--- | :--- |
| `dns_messages.csv` | Every DNS message with all parsed header fields |
| `dns_queries.csv` | Queries only (QR = 0) |
| `dns_responses.csv` | Responses only (QR = 1) |
| `dns_transactions.csv` | Matched pairs with latency, client/server, flags, answers |
| `domain_statistics.csv` | Domains ranked by query count and percentage |
| `query_type_statistics.csv` | A / AAAA / MX / TXT / PTR distribution |
| `response_code_statistics.csv` | NOERROR / NXDOMAIN / SERVFAIL distribution |
| `dns_analysis_summary.json` | Machine-readable summary of all of the above |
| `project_report.md` | Academic report generated from the analysed capture |

---

## 6. Your real capture — results and how to read them

Capture: `my_capture.pcapng`, 85.54 s, 2026-11-11 19:32:10 → 19:33:36 UTC.

| Metric | Value | Interpretation to say out loud |
| :--- | :--- | :--- |
| Total packets | 1,761 | Everything on the adapter during the window |
| DNS packets | 120 (61 queries, 59 responses) | Only 6.8% of traffic is DNS |
| Non-DNS packets | 1,641 | HTTPS/TCP/ARP — correctly ignored by the parser |
| Unique domains | 31 | Distinct names queried |
| Matched transactions | 55 | 90% of queries got a correlated reply |
| Unanswered / unmatched | 4 / 4 | Capture-window boundaries and multicast mDNS |
| Retransmissions | 2 | Same query sent twice before the reply |
| Mean latency | 21.11 ms | Pulled up by a few slow lookups |
| Median latency | 5.71 ms | Typical lookup is very fast (local resolver/cache) |
| p95 latency | 71.19 ms | 95% of lookups faster than this |
| Max latency | 407.78 ms | The deliberately non-existent domain |
| Transport | 97.5% UDP, 2.5% TCP | TCP used for larger/truncated responses |

**Distributions:**

- Query types: A 27 (44.3%), PTR 11 (18.0%), AAAA 10 (16.4%), HTTPS 9 (14.8%), MX 2, TXT 2.
- Response codes: NOERROR 39 (66.1%), NXDOMAIN 20 (33.9%).
- Answer record types: CNAME 24 (48%), A 22 (44%), AAAA 3 (6%), TXT 1 (2%).
- Top domains: `1.1.168.192.in-addr.arpa` ×7 (reverse lookup of 192.168.1.1 — the router),
  `_arduino._tcp.local` ×4 (mDNS device discovery), `example.com.bbrouter` ×3,
  `example.com` ×3, then Microsoft/Bing/Xbox service domains.

**Three observations you can present as analysis:**

1. **CNAME dominates the answer types (48%).** Microsoft/Xbox domains are served through CDNs, so
   a single A query often returns a CNAME chain plus the final A record. This proves why *requested*
   type and *returned* type must be counted separately.
2. **33.9% NXDOMAIN is not a fault.** The capture includes `nonexistent-domain-847291.example`
   (deliberate), router search-suffix attempts like `example.com.bbrouter`, and mDNS/NetBIOS-style
   names. This is normal on a Windows machine.
3. **Mean (21.11 ms) ≫ median (5.71 ms).** A handful of slow lookups — led by the 407.78 ms
   NXDOMAIN, where the resolver had to prove the name does not exist — skew the average. That is
   exactly why the dashboard reports median and p95 alongside the mean.
4. **mDNS is why 4 queries look unanswered.** `_arduino._tcp.local` is multicast to
   `224.0.0.251:5353`; replies come from a different source IP/port, so the strict 5-tuple
   correlator deliberately does not force a match. Reporting them as *unmatched* is the honest
   result, not a missed response.

---

## 7. Likely teacher questions — short answers

**Q: Why not just use Wireshark's statistics menu?**
A: Wireshark shows per-packet detail and some built-in counters, but it does not compute
query→response latency per transaction, pair requests with replies across transaction-ID reuse,
or export a reproducible CSV/JSON/report. This project adds that analysis layer.

**Q: How do you know a response belongs to a query?**
A: Same 16-bit ID, inverted 5-tuple (client/server IPs and ports swapped), matching domain name,
and timestamp causality (`T_response ≥ T_query`) inside a 30 s window. Anything else stays unmatched.

**Q: Why can latency be wrong if you only use the transaction ID?**
A: IDs are only 16 bits and get reused quickly. Two clients (or two queries from one client) can
share an ID; matching only on ID would pair the wrong packets and could even produce negative
latency. The 5-tuple and time check prevent that — and there is a test for it.

**Q: What happens with DNS-over-HTTPS?**
A: DoH/DoT traffic is encrypted inside TLS on ports 443/853, so the DNS layer never appears. Those
lookups are simply invisible; the report lists this as a limitation.

**Q: Why are some queries unanswered?**
A: The reply can arrive after the capture stopped, be answered from the OS/browser cache, or be
sent to a multicast address where the responder uses a different source socket. The tool reports
"unmatched", never "failed".

**Q: Is the data real?**
A: Yes — `my_capture.pcapng` is a Wireshark capture from my machine. The only synthetic file is
`script/generate_test_capture.py`, used exclusively for automated tests and clearly labelled.

**Q: How is the latency percentile computed?**
A: `numpy.percentile` over the matched latencies; mean, median, min, max and standard deviation
come from the same array. Nothing is hard-coded.

**Q: What are the limitations?**
A: Only visible traffic is analysed; encrypted DNS is opaque; OS caching hides repeat lookups;
measured latency includes network and resolver time, not just server processing.

---

## 8. One-sentence conclusion

> "The project turns a raw Wireshark capture into defensible DNS metrics — parsed per RFC 1035,
> correlated with a collision-safe 5-tuple algorithm, validated by 20 automated tests, and
> presented in a dashboard that exports the same numbers as CSV, JSON and a written report."
