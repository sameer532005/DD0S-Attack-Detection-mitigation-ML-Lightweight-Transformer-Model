# SDN DDoS Detection and Mitigation with Ryu, Mininet, and Random Forest

This project demonstrates a simple end-to-end SDN security pipeline:

`Mininet Network -> Ryu Controller -> Flow Statistics -> CSV Dataset -> Random Forest -> Detection -> OpenFlow Mitigation`

It is designed for Ubuntu with Mininet, Open vSwitch, Ryu, and Python.

## Files

- `topology.py`: creates a multi-host, multi-switch Mininet network connected to Ryu on port `6653`.
- `switch.py`: plain L2 learning switch for connectivity testing.
- `controller.py`: L2 learning switch plus flow-stat collection, ML prediction, and DDoS mitigation.
- `train_model.py`: trains and saves a Random Forest classifier from CSV flow statistics.
- `requirements.txt`: Python dependencies.

## Install

On Ubuntu:

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch hping3 python3-pip
python3 -m pip install -r requirements.txt
```

If OVS is not already running:

```bash
sudo service openvswitch-switch start
```

## Quick Connectivity Test

Terminal 1:

```bash
ryu-manager --ofp-tcp-listen-port 6653 switch.py
```

Terminal 2:

```bash
sudo python3 topology.py
```

Inside the Mininet CLI:

```bash
pingall
h1 ping -c 5 h6
```

Exit Mininet with:

```bash
exit
```

Clean Mininet if needed:

```bash
sudo mn -c
```

## Collect a CSV Dataset

Start the ML controller without a model. It will collect CSV rows and print debug messages:

```bash
TRAFFIC_LABEL=0 ryu-manager --ofp-tcp-listen-port 6653 controller.py
```

In another terminal:

```bash
sudo python3 topology.py
```

Generate normal traffic in the Mininet CLI:

```bash
h1 ping -c 20 h6
h2 ping -c 20 h5
h3 iperf -s &
h1 iperf -c 10.0.0.3 -t 20
```

Stop the controller, then restart it with label `1` while generating attack traffic:

```bash
TRAFFIC_LABEL=1 ryu-manager --ofp-tcp-listen-port 6653 controller.py
```

Attack examples inside Mininet:

```bash
h1 hping3 -S --flood -p 80 10.0.0.6
h2 hping3 --icmp --flood 10.0.0.6
h3 hping3 --udp --flood -p 53 10.0.0.6
```

Stop `hping3` with `Ctrl+C`. The collected dataset is stored in `flow_stats.csv`.

## Train the Random Forest Model

Train on your collected dataset:

```bash
python3 train_model.py --dataset flow_stats.csv --model ddos_random_forest.joblib
```

The script performs a train-test split, prints the confusion matrix, prints accuracy, and saves the model.

For a quick pipeline dry run before collecting real traffic:

```bash
python3 train_model.py --generate-sample --dataset sample_flow_stats.csv --model ddos_random_forest.joblib
```

The synthetic sample is only for checking that the code runs. For a real demo, train with Mininet-collected traffic.

## Real-Time Detection and Mitigation Demo

Terminal 1:

```bash
ryu-manager --ofp-tcp-listen-port 6653 controller.py
```

Terminal 2:

```bash
sudo python3 topology.py
```

Generate normal traffic:

```bash
h1 ping -c 10 h6
```

Launch an attack:

```bash
h1 hping3 -S --flood -p 80 10.0.0.6
```

Expected controller output includes lines like:

```text
DETECTION: DDoS traffic predicted from 10.0.0.1 to 10.0.0.6
MITIGATION: installed drop rule on s1 for attacker IP 10.0.0.1
```

## How the Components Interact

1. `topology.py` starts a Mininet network with hosts and OVS switches.
2. Each OVS switch connects to the Ryu controller at `127.0.0.1:6653` using OpenFlow 1.3.
3. `controller.py` behaves like a learning switch, so hosts can communicate.
4. Every 5 seconds, the controller asks switches for flow statistics.
5. The controller extracts source IP, destination IP, protocol, packet count, byte count, duration, packet rate, and byte rate.
6. The features are appended to `flow_stats.csv`.
7. `train_model.py` trains a Random Forest model using labeled rows: `0` for legitimate traffic and `1` for DDoS traffic.
8. After `ddos_random_forest.joblib` exists, `controller.py` loads it automatically.
9. During live traffic, each collected flow is classified as legitimate or DDoS.
10. If DDoS is detected, the controller installs a high-priority OpenFlow drop rule for the attacker source IP.

## Notes for a Beginner Demo

- Use `switch.py` first to confirm Mininet and Ryu are working.
- Use `controller.py` without a model to collect data.
- Use `TRAFFIC_LABEL=0` for normal traffic and `TRAFFIC_LABEL=1` while deliberately running `hping3`.
- The model quality depends on your labeled dataset. Collect enough normal and attack examples for better results.
- If Mininet behaves strangely after a crash, run `sudo mn -c`.
