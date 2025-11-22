from scapy.all import sniff, IP, TCP, UDP, Raw

LOG_FiLE = "packet_log.txt"
SUSPICIOUS_PORTS = [80,23,21]


#Logging function
def log_packet(message):
    print(message)
    
    with open(LOG_FiLE, "a") as f:
        f.write(message + "\n")
        

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            if dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS:
                log_packet(f"‼️ ALERT: Suspicious Activity Detected! IP {src_ip} -> {dst_ip} used Source Port: {src_port} and Des Port: {dst_port}")
            
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
         
        if protocol != "OTHER":
            log_packet(f"Packet: Protocol {protocol}: {src_ip} -> {dst_ip}")

def main():
    sniff(prn=packet_callback, store=0)
    

if __name__ == "__main__":
    main()
