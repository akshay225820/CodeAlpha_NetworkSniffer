# network_sniffer_improved.py


from scapy.all import (
    sniff, Ether, IP, TCP, UDP, ICMP, Raw,
    wrpcap, get_if_list, conf
)
import datetime
import sys


iface = None

BPF_FILTER = "ip"   

MAX_PACKETS = 0


PCAP_FILENAME = "capture_output.pcap"
LOG_FILENAME = "packet_log.txt"
# ----------------------------------

def show_interfaces():
    print("Available network interfaces:")
    for i, name in enumerate(get_if_list()):
        default_mark = " (default)" if name == conf.iface else ""
        print(f"  [{i}] {name}{default_mark}")

def try_decode_payload(raw_bytes):
    
    try:
        text = raw_bytes.decode("utf-8")
        return text
    except Exception:
        try:
            return raw_bytes.decode("latin-1", errors="replace")
        except Exception:
           
            return raw_bytes[:100].hex()

def packet_callback(pkt):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[+] Packet Captured at {ts}")
   
    if Ether in pkt:
        eth = pkt[Ether]
        print(f"Ether: {eth.src} -> {eth.dst} | type=0x{eth.type:04x}")

    if IP in pkt:
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
        print(f"Source IP: {src}")
        print(f"Destination IP: {dst}")
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"Other ({proto})")
        print(f"Protocol: {proto_name}")

        
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            print(f"TCP Ports: {t.sport} -> {t.dport} | Flags: {t.flags}")
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            print(f"UDP Ports: {u.sport} -> {u.dport}")

        
        if pkt.haslayer(Raw):
            raw = pkt[Raw].load
            preview = try_decode_payload(raw)
            # truncate long output
            if isinstance(preview, str) and len(preview) > 300:
                preview = preview[:300] + " ... [truncated]"
            print(f"Payload (preview):\n{preview}")
        else:
            print("No Raw payload layer.")

    else:
        
        print("Non-IP Packet Type Captured")
        print(pkt.summary())

    # Also append a short log entry to file
    try:
        with open(LOG_FILENAME, "a", encoding="utf-8") as f:
            if IP in pkt:
                f.write(f"{ts} | {pkt[IP].src} -> {pkt[IP].dst} | proto={pkt[IP].proto}\n")
            else:
                f.write(f"{ts} | Non-IP | {pkt.summary()}\n")
    except Exception as e:
        print(f"Warning: failed to write log: {e}")


def main():
    global iface
    print("Scapy conf.iface:", conf.iface)
    show_interfaces()
    if iface is None:
        print("\nUsing default interface. To choose another, set 'iface' variable in the script.")
    else:
        print(f"\nUsing interface: {iface}")

    print(f"\nStarting network sniffer... Press CTRL+C to stop.\nFilter: '{BPF_FILTER or 'NONE (all frames)'}'")

    
    try:
        packets = sniff(
            prn=packet_callback,
            iface=iface,
            filter=BPF_FILTER if BPF_FILTER else None,
            store=True,
            count=MAX_PACKETS if MAX_PACKETS > 0 else 0
        )
    except Exception as e:
        print("Error starting sniff():", e)
        print("Try running VS Code as Administrator and ensure Npcap is installed.")
        sys.exit(1)

    
    try:
       
        if packets:
            print(f"\nCaptured {len(packets)} packets. Saving to {PCAP_FILENAME} ...")
            wrpcap(PCAP_FILENAME, packets)
            print("PCAP saved.")
        else:
            print("No packets captured.")
    except KeyboardInterrupt:
        
        try:
            if 'packets' in locals() and packets:
                print(f"\nCaptured {len(packets)} packets. Saving to {PCAP_FILENAME} ...")
                wrpcap(PCAP_FILENAME, packets)
                print("PCAP saved.")
        except Exception as e:
            print("Error saving PCAP:", e)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user. Attempting to save pcap (if any) and exit.")
        
        sys.exit(0)
