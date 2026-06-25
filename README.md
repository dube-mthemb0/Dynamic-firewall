Dynamic Reinforcement Learning Firewall - User Guide
This guide provides a straightforward, step-by-step walkthrough for setting up, running, and managing your autonomous reinforcement learning firewall and interactive telemetry dashboard.

🧠 System Overview and Key Features
This application pairs an autonomous network-layer firewall with a live monitoring dashboard. It sniffs active network traffic, processes it through machine learning models, and synchronizes system behavior using a bidirectional file-system bridge.

Live Traffic Analysis: Captures and extracts 40-dimensional features from network data streams using Scapy.

Intelligent Decisions: Deploys trained deep reinforcement learning models (DQN/PPO) to dynamically block or allow traffic.

Bidirectional Control Plane: Syncs manual blocking rules added on the web user interface down to the live firewall loop instantly.

Real-time Telemetry: Renders performance counters, active protocols, and decision distributions every 2 seconds.

🚀 Local Environment Installation
Follow these steps to configure the software natively on your Linux distribution or WSL2 environment.

1. Project Initialization
Clone your repository or navigate into the core folder, then set up your local execution environment:

Bash
cd ~/Dynamic-firewall
python3 -m venv .venv
source .venv/bin/activate
2. Dependency Management
Upgrade your package manager and install the core framework libraries:

Bash
pip install --upgrade pip
pip install -r requirements.txt
💻 Standard Operation Modes
Always ensure your virtual environment is active (source .venv/bin/activate) before running commands. Because network sniffing interacts with kernel-level sockets, packet modes require root privileges.

Packet Capture Diagnostic Mode
Test your underlying network hooks and see raw incoming frames without making enforcement modifications:

Bash
sudo .venv/bin/python3 main.py --mode capture
Model Training Mode
Train your reinforcement learning agent against local dataset archives to generate a fresh 40-dimensional execution checkpoint:

Bash
.venv/bin/python3 main.py --mode train --dataset data/cicids2017
Live Intelligent Firewall Mode
Run the core defensive loop. This process sniffs live traffic, applies your model checkpoints, and updates your shared logging bridge:

Bash
sudo .venv/bin/python3 main.py --mode firewall
Telemetry Dashboard Mode
Launch the interactive web portal to monitor the running system. This runs in user space and does not require root privileges:

Bash
.venv/bin/python3 src/dashboard/app.py
Viewing the UI: Once launched, open your preferred web browser and navigate to http://127.0.0.1:8050.

🧪 Containerized Testing Environment
If you prefer to run the core firewall engine inside an isolated container loop instead of installing software on your host machine, use the integrated Docker build pipes.

1. Spin up the background container infrastructure
Bash
sudo docker-compose up -d --build testing-environment
2. Monitor live container decisions and packet streams
Bash
sudo docker-compose logs -f testing-environment
3. Track container states
Bash
sudo docker-compose ps
Data Synchronization: The container automatically passes data metrics to your host machine via a shared storage volume. Keep your local dashboard running (python3 src/dashboard/app.py) to watch the containerized metrics update live in your browser.

📊 Managing Rules and Interacting with the UI
The system uses a highly responsive data layout divided into three main operational pillars when viewed in your browser:

System Gauges (Left): Displays aggregated totals for packets processed, allowed, and blocked, along with active host memory and CPU utilization rates.

Throughput Visualizers (Center): Generates live temporal graphs mapping packets per second (PPS) and interactive pie charts sorting traffic across network protocols (TCP, UDP, ICMP).

Firewall Rules Table (Right): Renders active access control lists. You can input custom names or IP boundaries, select an action (ALLOW, DROP, LOG, QUARANTINE), and click Add Rule to inject custom policies directly into the engine's active packet evaluation logic.
