# Zyra SIEM — Data Flow Diagrams (DFD)

This file contains the **4 DFD levels (0–3)** for ZyraSIEM, extracted from `README.md`.

## How to view these diagrams

- **On GitHub/GitLab**: Mermaid code blocks typically render automatically.
- **In Cursor/VS Code**: install a Mermaid preview extension (or use the Markdown preview if Mermaid is supported).

## How to export to image files (PNG/SVG)

If you want **actual diagram files**, you can export Mermaid to images using Mermaid CLI:

```bash
npm i -g @mermaid-js/mermaid-cli
```

Then export (example):

```bash
mmdc -i dfd.md -o dfd.pdf
```

Tip: Mermaid CLI works best when you copy each Mermaid block into its own `.mmd` file (e.g., `dfd-level-0.mmd`) and export one-by-one to `svg` or `png`.

---

## ASCII diagrams (underscore style)

These are the same flows, but drawn with **`_` and `|`** (ASCII boxes) instead of Mermaid.

### ASCII DFD Level 0 (Context)

```
  _______________            ______________________
 |               |          |                      |
 |   ENDPOINT    |--------->|     ZYRA  SIEM       |
 |_______________|          |______________________|
         ^                         ^        ^
         |                         |        |
         |                         |        |
  _______________            ______________  __________________
 |               |          |              ||                  |
 |    ANALYST    |<-------->|    MONGODB   ||  VT / IPINFO     |
 |_______________|          |______________||__________________|
```

### ASCII DFD Level 1 (System decomposition)

```
  _______________                 ________________________________
 |               |               |                                |
 |   ENDPOINT    |-------------->|  (1) AGENT  agent.py (Admin)   |
 |_______________|               |________________________________|
                                        |           |
                                        | logs+     | alerts+
                                        v           v
                               __________________   __________________
                              |                  | |                  |
                              |   MONGODB (D1)    | |   SQLITE (D2)    |
                              |__________________| |__________________|
                                        ^                 |
                                        | sync             | offline store
                                        |                  |
                                        |__________________|

  ___________________           ____________________________           ____________________
 |                   |         |                            |         |                    |
 | (3) DASHBOARD      |<------->| (2) API SERVER server.py   |<------->|  SECURITY ANALYST  |
 | app.py  :5001      |  REST/WS|  :5000  /api/v1 + /ws      |   UI     | (browser)         |
 |___________________|         |____________________________|         |____________________|
```

## DFD Level 0 (Context)

```mermaid
flowchart LR
  Analyst[Security Analyst] <-->|Views dashboards / investigates| Zyra((Zyra SIEM))
  Endpoint[Windows Endpoint] -->|Telemetry & events| Zyra
  VT[VirusTotal] <-->|Threat intel lookups| Zyra
  IPInfo[ipinfo.io] <-->|IP enrichment| Zyra
  Mongo[(MongoDB)] <-->|Store / query| Zyra
```

## DFD Level 1 (System decomposition)

```mermaid
flowchart LR
  subgraph External["External"]
    Analyst[Security Analyst]
    Endpoint[Windows Endpoint]
    VT[VirusTotal]
    IPInfo[ipinfo.io]
  end

  subgraph ZyraSIEM["Zyra SIEM"]
    P1["1. Endpoint Agent agent.py"]
    P2["2. API Server server.py"]
    P3["3. Dashboard Web App app.py"]
    D1["MongoDB zyra_siem"]
    D2["SQLite Offline Store local_storage.db"]
  end

  Endpoint -->|metrics / logs / network / processes| P1
  P1 -->|device_info upsert| D1
  P1 -->|logs documents| D1
  P1 -->|alerts documents| D1
  P1 -->|offline logs/alerts| D2
  D2 -->|sync when online| D1

  P1 <-->|VT hash lookups (optional)| VT
  P1 <-->|IP enrichment (optional)| IPInfo

  P2 -->|query logs/alerts/devices| D1
  P3 -->|REST calls /api/v1/*| P2
  P3 <-->|WS /ws/dashboard| P2
  Analyst <-->|Browser UI| P3
```

## DFD Level 2 (Agent internals)

```mermaid
flowchart TB
  subgraph Agent["Windows Agent (agent.py)"]
    A1["Collect system metrics<br/>(psutil)"]
    A2["Read Windows Event Logs<br/>(System/Security)"]
    A3["Capture DNS + traffic hints<br/>(scapy + Npcap)"]
    A4["Process monitoring<br/>+ optional VT checks"]
    A5["Registry monitoring<br/>(Run key)"]
    A6["Anomaly detection<br/>(rule-based)"]
    A7["Persist + sync<br/>(MongoDB or SQLite)"]
  end

  OS[(Windows OS)] --> A1
  OS --> A2
  Net[(Network stack)] --> A3
  OS --> A4
  OS --> A5

  A1 --> Q[(In-memory queues)]
  A2 --> Q
  A3 --> Q
  A4 --> Q
  A5 --> Q

  Q --> A6
  Q --> A7
  A6 -->|alerts| A7

  D1[(MongoDB)] <-->|online writes| A7
  D2[(SQLite local_storage.db)] <-->|offline writes / later sync| A7
  VT[VirusTotal] <-->|optional lookup| A4
  IPInfo[ipinfo.io] <-->|IP enrichment| A3
```

## DFD Level 3 (Alerting & storage pipeline detail)

```mermaid
flowchart LR
  subgraph Pipeline["Agent alerting + storage pipeline"]
    S1["1. Gather latest telemetry<br/>from queues"]
    S2["2. Normalize into a<br/>log_data document"]
    S3["3. Detect anomalies<br/>(rules)"]
    S4["4. Persist logs + alerts"]
    S5["5. Offline sync worker"]
  end

  S1 --> S2
  S2 -->|log_data| S4
  S2 --> S3
  S3 -->|alerts list| S4

  Mongo["MongoDB logs alerts device_info"] <-->|insert_one / insert_many| S4
  SQLite["SQLite local_storage.db"] <-->|store_locally| S4
  SQLite -->|read unsent rows| S5
  S5 -->|insert_many + clear| Mongo
```

