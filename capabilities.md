# 🛠️ Platform Capabilities: Defensive Cybersecurity Monitoring Platform

This document outlines the current functional capabilities of the defensive security platform.

## 🏗️ Infrastructure & Core
- **Containerized Orchestration:** Fully deployed using Docker Compose for rapid deployment and scalability.
- **Distributed Log Storage:** Utilizes **OpenSearch** for high-performance indexing and searching of security telemetry.
- **Data Visualization:** Integrated **OpenSearch Dashboards** for real-time monitoring and alert visualization.
- **Asset Management:** **PostgreSQL** backend to track agent metadata, enrollment status, and last-seen timestamps.
- **Asynchronous Messaging:** **Redis** queue implementation to decouple data ingestion from processing, ensuring high availability under load.

## 📡 Telemetry & Monitoring
- **Multi-OS Endpoint Telemetry:** Support for **Windows** and **Linux** endpoints.
    - **System Stats:** Real-time collection of CPU usage and Memory consumption.
    - **OS Identification:** Automatic detection of Hostname, OS type, and Kernel release.
    - **Process Monitoring:** Tracking of top resource-consuming processes (PID, Name, User, Memory %).
- **Agentless Ingestion:** Integrated **Syslog receiver** for collecting logs from network devices and legacy systems without agent installation.

## 🎮 Command & Control (C2)
- **Interactive C2 Console:** Dedicated CLI management tool for administrators to list agents and dispatch commands.
- **Remote Execution:** Ability to push arbitrary shell commands to specific endpoints.
- **Asynchronous Polling:** Agents poll for pending commands at regular intervals, allowing communication through firewalls (outbound only).
- **Result Exfiltration:** Command output (stdout/stderr) and return codes are captured and sent back to the platform as telemetry events.

## 🔐 Security & Authentication
- **Secure Enrollment Flow:** A "registration secret" handshake allows new agents to join the platform securely.
- **Token-Based Auth:** Each agent is issued a unique, cryptographically strong API token upon enrollment, stored locally in `agent.token`.
- **Identity Verification:** Every request to the ingest API is validated against the token and `agent_id` to prevent spoofing.
- **Administrative Access:** Dedicated admin keys for sending C2 commands.
- **Database Hardening:** Password-protected PostgreSQL and Redis instances.

## 🚀 Workflow Summary
`Agent` $\rightarrow$ `Secure Enrollment` $\rightarrow$ `Unique Token` $\rightarrow$ `Telemetry/C2 Polling` $\rightarrow$ `FastAPI` $\rightarrow$ `Redis` $\rightarrow$ `OpenSearch` $\rightarrow$ `Dashboard/C2 Console`
