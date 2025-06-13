
###  Requirements

Make sure you have the following installed before running the script:

* Python 3.x
* [Scapy](https://scapy.net/)
* Root privileges (required for raw packet sniffing)

To install Scapy, run:

```bash
pip install scapy
```

---

###  Usage

Run the script with Python 3 and specify your options:

```bash
sudo python3 sniffer.py [-i INTERFACE] [-p PROTOCOL]
```

#### Arguments:

* `-i`, `--interface`: (Optional) Network interface to sniff on (e.g., `eth0`, `wlan0`)
* `-p`, `--protocol`: (Optional) Protocol filter – `tcp` or `udp`

#### Examples:

Sniff all traffic on the default interface:

```bash
sudo python3 sniffer.py
```

Sniff only TCP traffic on `eth0`:

```bash
sudo python3 sniffer.py -i eth0 -p tcp
```

Sniff only UDP traffic on `wlan0`:

```bash
sudo python3 sniffer.py -i wlan0 -p udp
```

---

