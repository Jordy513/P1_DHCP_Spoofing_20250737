# Capturas de pantalla — DHCP Spoofing

Capturas del laboratorio en orden de demostración.

| Archivo | Descripción |
|---------|-------------|
| `01_topologia.png` | Topología en PNETLab con nombre y matrícula visibles |
| `02_pool_agotado.png` | R1 mostrando `show ip dhcp pool` con `Available: 0` tras el Starvation |
| `03_spoofing_ejecutandose.png` | Kali con el servidor Rogue activo interceptando Discovers |
| `04_exito_ataque.png` | Kali mostrando `[+] ¡ÉXITO!` con IP y GW asignados a la víctima |
| `05_victima_ip_falsa.png` | Docker víctima con `ip a` mostrando `20.25.37.50` y GW `20.25.37.100` |
| `06_contramedida_aplicada.png` | DHCP Snooping configurado en SW2 |
| `07_post_mitigacion.png` | Víctima obteniendo IP legítima de R1 tras la contramedida |
