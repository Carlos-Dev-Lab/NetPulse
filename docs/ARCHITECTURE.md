# Arquitectura

## Objetivos

La refactorización reduce el acoplamiento del antiguo `main.py` monolítico y
establece dependencias dirigidas hacia el dominio. La captura, SQLite y Flet
quedan en los bordes del sistema para que la agregación sea comprobable sin
Npcap, red ni interfaz gráfica.

## Capas

- `domain`: contiene `Packet`, `AppState`, `NetworkScan`, `ScanHost`,
  `ScanService` y contratos mínimos. No importa Flet, Scapy, psutil, Nmap ni
  SQLite.
- `infrastructure`: implementa captura, ejecucion y parseo XML de Nmap y
  persistencia. Puede depender del dominio, pero el dominio no depende de esta
  capa.
- `services`: ejecuta enriquecimiento DNS/geográfico fuera del hilo de UI.
- `presentation`: compone dependencias, maneja eventos y renderiza vistas.

## Decisiones

1. `Packet` se movió al dominio para evitar que la lógica de agregación importe
   Scapy o psutil indirectamente.
2. `AppState` recibe un enriquecedor por inyección. En pruebas usa una
   implementación nula; en producción recibe `IpInfoCache`.
3. La base se ubica en `data/netpulse.db`, calculada desde el proyecto, para no
   depender del directorio desde el que se inicia el proceso.
4. La persistencia acumula los cinco intervalos de 200 ms antes de escribir el
   resumen por segundo. Los contadores por IP usan deltas, evitando duplicar
   totales acumulados en cada upsert.
5. Existe un único punto de entrada, `python -m netpulse`; el punto de
   composición real vive en `netpulse.presentation.app`.
6. La captura pasiva y el escaneo activo son flujos independientes. Scapy
   alimenta indicadores en tiempo real; Nmap produce instantaneas auditables y
   comparables bajo demanda.
7. Nmap se ejecuta con una lista de argumentos y salida XML. No se usa una
   shell ni se interpreta texto orientado a humanos, reduciendo riesgos de
   inyeccion y fragilidad ante cambios de formato.
8. El riesgo se calcula en infraestructura a partir de puertos expuestos,
   servicios detectados y hallazgos NSE. La presentacion solo transforma ese
   resultado en indicadores visuales.
9. Los escaneos se normalizan en `network_scans`, `scan_hosts`,
   `scan_services` y `scan_alerts`. Esto permite consultar historial y cambios
   sin almacenar XML opaco como fuente unica.

## Elementos eliminados

- El `main.py` monolítico de aproximadamente 2.000 líneas.
- El modelo `Packet` duplicado dentro del adaptador de captura.
- `DB.upsert_ip`, sin consumidores y redundante frente a `upsert_ips`.
- Imports globales mezclados de UI, red, persistencia y utilidades.
- `main.py` y los wrappers de arranque duplicados; `scripts/start.bat` y
  `python -m netpulse` abren una única aplicación nativa de escritorio.

## Reglas de evolución

- El dominio no debe importar módulos de `presentation` o `infrastructure`.
- Las consultas externas deben permanecer asíncronas y no bloquear Flet.
- Los escaneos activos deben ejecutarse fuera del hilo de UI, tener timeout y
  validar el objetivo antes de iniciar Nmap.
- Los cambios de esquema deben introducir migraciones explícitas.
- La lógica nueva de agregación debe cubrirse con pruebas sin captura real.
- Los nuevos perfiles Nmap deben declarar su alcance y costo para evitar
  escaneos sorpresivamente invasivos o lentos.
