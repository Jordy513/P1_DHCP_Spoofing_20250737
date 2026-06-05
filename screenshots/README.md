# Capturas de pantalla — DHCP Spoofing

Capturas del laboratorio en orden de demostración.

| # | Archivo | Descripción |
|---|---------|-------------|
| 1 | [01_topologia.png](screenshots/01_topologia.png) | Topología en PNETLab con nombre y matrícula visibles |
| 2 | *Opcional* - [02_pool_agotado.png](screenshots/02_pool_agotado.png) | R1 mostrando `show ip dhcp pool` con `Available: 0` tras el Starvation |
| 3 | [03_spoofing_ejecutandose.png](screenshots/03_spoofing_ejecutandose.png) | Kali con el servidor Rogue activo interceptando Discovers |
| 4 | [04_exito_ataque.png](screenshots/04_exito_ataque.png) | Kali mostrando `[+] ¡ÉXITO!` con IP y GW asignados a la víctima |
| 5 | [05_victima_ip_falsa.png](screenshots/05_victima_ip_falsa.png) | Docker víctima con `ip a` mostrando `20.25.37.50` y GW `20.25.37.100` |
| 6 | [06_contramedida_aplicada.png](screenshots/06_contramedida_aplicada.png) | DHCP Snooping configurado en SW2 |
| 7 | [07_post_mitigacion.png](screenshots/07_post_mitigacion.png) | Víctima obteniendo IP legítima de R1 tras la contramedida |
