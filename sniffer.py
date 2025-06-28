from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
from colorama import init, Fore

init()

GREEN = Fore.GREEN
RED = Fore.RED
CYAN = Fore.CYAN
YELLOW = Fore.YELLOW
RESET = Fore.RESET

def sniff_packets(iface=None):
    """
    Captura tráfico de red para múltiples protocolos conocidos.
    """
    print(f"{CYAN}[*] Iniciando sniffer...{RESET}")
    # Filtros: DNS (53), FTP (21), HTTP (80)
    sniff(filter="port 53 or port 21 or port 80", prn=process_packet, iface=iface, store=False)

def process_packet(packet):

    # ======== HTTP ========
    if packet.haslayer(HTTPRequest) and packet.haslayer(IP):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        ip = packet[IP].src
        method = packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN}[HTTP] {ip} -> {url} ({method}){RESET}")

    # ======== DNS ========
    elif packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 and packet.haslayer(IP):  # DNS query (no respuesta)
        ip = packet[IP].src
        query = packet[DNSQR].qname.decode()
        print(f"{YELLOW}[DNS] {ip} está preguntando por {query}{RESET}")

    # ======== FTP ========
    elif packet.haslayer(TCP) and packet.haslayer(IP):
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        if dport == 21 or sport == 21: 
            ip = packet[IP].src
            payload = str(bytes(packet[TCP].payload))
            print(f"{RED}[FTP] Paquete de {ip} -> Datos: {payload}{RESET}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Sniffer multiprotocolo (HTTP, DNS, FTP)")
    parser.add_argument("-i", "--iface", help="Interfaz de red a usar (ej. eth0, wlan0)")
    args = parser.parse_args()

    iface = args.iface
    sniff_packets(iface)
if packet.haslayer(HTTPRequest) and packet.haslayer(Raw):
    payload = packet[Raw].load.decode(errors='ignore')
    if "username" in payload or "password" in payload:
        print(f"{RED}[CREDENCIALES HTTP] {packet[IP].src} → {payload}{RESET}")
if "USER" in payload or "PASS" in payload:
    print(f"{RED}[CREDENCIALES FTP] {ip} → {payload}{RESET}")