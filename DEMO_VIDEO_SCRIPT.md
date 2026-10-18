# GraphGuard — five-minute hackathon demo

## Before recording

- Start Docker Desktop and confirm its engine is running.
- Start the existing FalkorDB container. For a first-time setup, create it with `docker run -d --name graphguard-falkordb -p 6379:6379 falkordb/falkordb`. If a container already uses port 6379, start that container instead of creating another one.
- In a second PowerShell window, go to the project folder. Seed the graph only if this is a fresh or empty database.
- Confirm the app is configured for the local database at `localhost:6379` and the Overview page shows FalkorDB connected.
- Record in landscape at 1080p. Keep terminal windows brief and never show API keys or `.env` contents.
- Graph counts can change as investigations are saved. Use the counts shown in the recording rather than hard-coding them.

### PowerShell commands

```powershell
cd C:\Users\dell\Desktop\wemakedevs\graphguard
.\.venv\Scripts\python.exe scripts\seed_demo.py   # only for a fresh/empty graph
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open `http://localhost:8501` in the browser. If the virtual environment or packages are not installed yet, follow the setup steps in `README.md` before recording.

## Timed shots and narration

### 00:00–00:25 — Introduction

**Show:** Start with the GraphGuard title or Overview page. Briefly show your avatar, then switch to the app.

**Say:**<br>
“Hi, I’m Krishna, and this is GraphGuard. Security teams often receive alerts one at a time, but an alert by itself rarely tells the whole story. An investigator needs to know which user, device, address, service, and incident connect to it. GraphGuard helps investigators follow those links and see the evidence around an alert.”

### 00:25–00:55 — Start the prototype

**Show:** Briefly show Docker Desktop running. Start the FalkorDB container, then open a second PowerShell window in the project folder. Show the seed command only for a fresh database, then launch Streamlit. Cut out waiting for startup.

**Say:**<br>
“To start the prototype, I first start Docker Desktop and FalkorDB, the graph database. In a second PowerShell window, I open the GraphGuard project folder. If this is a fresh database, I seed it once with the synthetic demo graph. Then I launch the Streamlit app and open it in my browser at localhost:8501. The green status confirms the app is connected to FalkorDB.”

### 00:55–01:20 — The synthetic environment and dashboard

**Show:** Point briefly to the connected database status, graph counts, recent alerts, incidents, and investigations.

**Say:**<br>
“This demo uses synthetic security data in FalkorDB. The graph stores the entities and their relationships, so GraphGuard can search across those connections. The dashboard shows the current graph and investigation activity. Counts can change as investigations are saved, so these are the values for this run.”

### 01:20–02:15 — Investigate A-104

**Show:** Open **Investigate**, select **A-104**, and click **Investigate**. Pause for the result, then show the summary and graph path.

**Say:**<br>
“I’ll investigate alert A-104, which describes suspicious outbound activity from an engineering workstation. Instead of looking at A-104 by itself, I’m asking whether it is connected to other activity. GraphGuard follows the relationships in the database. The alert leads to WORKSTATION-07 and its user, Marcus Chen. The workstation contacted 185.220.101.45, which the synthetic data marks as a malicious Tor exit node. The alert is linked to incident INC-001, a suspected data-exfiltration incident. This is the kind of context a single alert lookup would miss.”

### 02:15–02:55 — Follow related activity

**Show:** Scroll to **Related Alerts** and the graph evidence path. Point out A-105 and A-106.

**Say:**<br>
“The graph also finds related alerts through shared relationships. A-105 is a port-scan alert from the same workstation. A-106 is a C2 beacon attempt associated with the same IP address. All three alerts connect to INC-001. This gives the analyst a sequence of related activity to investigate, rather than three disconnected alert records.”

### 02:55–03:40 — Evidence, impact, and uncertainty

**Show:** Scroll across **Confirmed Facts**, **Inferences**, **Unknowns**, **Supporting Evidence**, and **Potentially Affected Services**. Pause on the two services.

**Say:**<br>
“GraphGuard separates confirmed facts from inferences and unknowns. The supporting evidence includes network, firewall, and threat-intelligence records. The incident is connected to the Payment Processing Service and the HR Employee Portal, so both are surfaced for review. Recommendations are suggestions for a human analyst; the prototype does not automatically block an IP or disable an account.”

### 03:40–04:15 — Compare a benign alert

**Show:** Return to **Investigate**, select **A-201**, and run the investigation.

**Say:**<br>
“Now compare that with A-201. This alert is connected to Alice Thompson’s laptop and the clean DNS address 8.8.8.8. The seeded data marks it as a false positive and shows no connected incident. The graph helps distinguish this benign scenario from the suspicious A-104 chain.”

### 04:15–04:40 — Persistent history

**Show:** Open **Investigation History** and show the saved A-104 investigation.

**Say:**<br>
“Investigations are saved in FalkorDB and can be retrieved from the history page. That means the investigation record can persist beyond this browser session, alongside the graph data it examined.”

### 04:40–05:00 — Close

**Show:** Return to Overview or hold on the A-104 graph path. End on the GraphGuard name and tagline.

**Say:**<br>
“GraphGuard connects the evidence around an alert, shows what the graph supports, and keeps uncertainty visible. Every alert has a story. Follow the graph to find it.”

## Demo Mode narration

If the app says **Demo Mode**, use this line:<br>
“This run uses GraphGuard’s deterministic graph-only flow. The graph queries and investigation display still work without a Gemini API key; live AI synthesis is optional.”

## Closing card

**GraphGuard**<br>
Every alert has a story. Follow the graph to find it.<br>
Graph Hacks 2026 · Synthetic demo data
