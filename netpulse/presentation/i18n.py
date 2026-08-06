"""NetPulse internationalization engine.

English source strings are stable translation keys. Add a language by creating
one catalog and registering it in ``CATALOGS``; views do not need rebuilding.
"""

import flet as ft


ES = {
    "Overview": "Resumen", "Network": "Red", "Packets": "Paquetes",
    "Local ports": "Puertos locales",
    "Analytics": "Analítica", "History": "Historial", "Apps": "Aplicaciones",
    "Settings": "Ajustes", "START": "INICIAR", "STOP": "DETENER",
    "STOPPED": "DETENIDO", "CAPTURING": "CAPTURANDO",
    "Network overview": "Resumen de red",
    "Live traffic, system health and active connections": "Tráfico en vivo, estado del sistema y conexiones activas",
    "Network discovery": "Descubrimiento de red",
    "Inventory devices, exposed services and topology changes": "Inventario de dispositivos, servicios expuestos y cambios de topología",
    "Packet explorer": "Explorador de paquetes",
    "Inspect, filter and export the live packet stream": "Inspecciona, filtra y exporta el flujo de paquetes en vivo",
    "Traffic analytics": "Analítica de tráfico",
    "Bandwidth trends and protocol distribution in real time": "Tendencias de ancho de banda y protocolos en tiempo real",
    "Session history": "Historial de sesiones",
    "Compare stored captures and review their top endpoints": "Compara capturas guardadas y sus principales destinos",
    "Application traffic": "Tráfico por aplicación",
    "See which local processes consume network bandwidth": "Consulta qué procesos locales consumen ancho de banda",
    "System settings": "Ajustes del sistema",
    "Capture source, alert thresholds and local storage": "Fuente de captura, alertas y almacenamiento local",
    "APPEARANCE": "APARIENCIA",
    "Customize the interface without restarting NetPulse.": "Personaliza la interfaz sin reiniciar NetPulse.",
    "Visual theme": "Tema visual", "Accent color": "Color de acento",
    "Interface density": "Densidad de la interfaz",
    "NetPulse dark": "Oscuro NetPulse", "Midnight blue": "Azul medianoche",
    "Graphite": "Grafito", "Pure black": "Negro puro",
    "Cyan": "Cian", "Blue": "Azul", "Green": "Verde",
    "Purple": "Morado", "Amber": "Ámbar",
    "Compact": "Compacta", "Standard": "Estándar",
    "Comfortable": "Cómoda", "APPLY APPEARANCE": "APLICAR APARIENCIA",
    "TOTAL PACKETS": "PAQUETES TOTALES", "MB RECEIVED ↓": "MB RECIBIDOS ↓",
    "MB SENT ↑": "MB ENVIADOS ↑", "PEAK BW": "PICO DE ANCHO DE BANDA",
    "CPU USAGE": "USO DE CPU", "RAM USAGE": "USO DE RAM",
    "LIVE TRAFFIC  ( KB/s )": "TRÁFICO EN VIVO  ( KB/s )",
    "PROTOCOL MIX": "DISTRIBUCIÓN DE PROTOCOLOS",
    "ACTIVE NETWORK DISCOVERY": "DESCUBRIMIENTO ACTIVO DE RED",
    "Target network": "Red objetivo", "Target networks": "Redes objetivo",
    "Scan method": "Método de escaneo",
    "SCAN NETWORK": "ESCANEAR RED", "Ready": "Listo",
    "DEVICES ONLINE": "DISPOSITIVOS EN LÍNEA", "OPEN PORTS": "PUERTOS ABIERTOS",
    "RISK LEVEL": "NIVEL DE RIESGO", "CHANGES": "CAMBIOS",
    "Scan history": "Historial de escaneos", "DEVICES AND SERVICES": "DISPOSITIVOS Y SERVICIOS",
    "ALERTS AND CHANGES": "ALERTAS Y CAMBIOS", "Protocol": "Protocolo",
    "DIAGNOSTIC CENTER": "CENTRO DE DIAGNÓSTICO",
    "CRITICAL ISSUES": "PROBLEMAS CRÍTICOS",
    "REQUIRES ATTENTION": "REQUIERE ATENCIÓN",
    "INFORMATIONAL": "INFORMATIVOS",
    "RESOLVED ISSUES": "PROBLEMAS RESUELTOS",
    "View device details": "Ver detalles del dispositivo",
    "OPEN PORTS AND SERVICES": "PUERTOS ABIERTOS Y SERVICIOS",
    "DIAGNOSIS AND RECOMMENDATIONS": "DIAGNÓSTICO Y RECOMENDACIONES",
    "No additional inventory data.": "No hay datos adicionales de inventario.",
    "No additional service details.": "No hay detalles adicionales del servicio.",
    "Open the device to view all services": "Abre el dispositivo para ver todos los servicios",
    "Run two scans to compare changes.": "Ejecuta dos análisis para comparar los cambios.",
    "No diagnostic information yet.": "Todavía no hay información de diagnóstico.",
    "No relevant changes detected.": "No se detectaron cambios relevantes.",
    "No active or recently resolved issues.": "No hay problemas activos ni resueltos recientemente.",
    "Select a device": "Selecciona un dispositivo",
    "Click a device IP to see its alerts and changes.": "Haz clic en la IP de un dispositivo para ver sus alertas y cambios.",
    "No alerts or changes for this device.": "No hay alertas ni cambios para este dispositivo.",
    "NETWORK MAP": "MAPA DE RED",
    "Segments and connections overview": "Resumen de segmentos y conexiones",
    "Select a node to view its alerts · Edit to complete inventory": "Selecciona un nodo para ver sus alertas · Edita para completar el inventario",
    "Run a scan to build the network map.": "Ejecuta un análisis para crear el mapa de red.",
    "Edit device inventory": "Editar inventario del dispositivo",
    "Custom name": "Nombre personalizado", "Device type": "Tipo de dispositivo",
    "EDIT DEVICE INVENTORY": "EDITAR INVENTARIO DEL DISPOSITIVO",
    "Identification and responsibility": "Identificación y responsabilidad",
    "Classification and notes": "Clasificación y notas",
    "CURRENT IP": "IP ACTUAL", "Previous IPs: ": "IP anteriores: ",
    "Owner": "Propietario", "Location": "Ubicación", "Notes": "Notas",
    "Trust status": "Estado de confianza", "Cancel": "Cancelar",
    "Save device": "Guardar dispositivo",
    "BEFORE VS NOW": "ANTES VS. AHORA",
    "A previous scan is required for comparison.": "Se necesita un análisis anterior para comparar.",
    "No comparison available.": "No hay una comparación disponible.",
    "Run the same target again to create a before-and-now comparison.": "Repite el mismo objetivo para crear una comparación entre antes y ahora.",
    "No topology or port changes detected.": "No se detectaron cambios de topología ni de puertos.",
    "Explain risk and verification": "Explicar riesgo y verificación",
    "WHY IT MATTERS": "POR QUÉ ES IMPORTANTE",
    "RECOMMENDED ACTION": "ACCIÓN RECOMENDADA",
    "SAFE VERIFICATION": "VERIFICACIÓN SEGURA",
    "Run verification only on networks you are authorized to assess.": "Ejecuta la verificación solo en redes para las que tengas autorización.",
    "Close": "Cerrar",
    "Global search": "Búsqueda global",
    "IP, MAC, hostname, process, port or application": "IP, MAC, hostname, proceso, puerto o aplicación",
    "SEARCH": "BUSCAR", "EXPORT REPORT": "EXPORTAR INFORME",
    "No matching results.": "No se encontraron resultados.",
    "Select a scan before exporting.": "Selecciona un análisis antes de exportar.",
    "Generating PDF, HTML and CSV reports...": "Generando informes PDF, HTML y CSV...",
    "Reports exported to exports folder.": "Informes exportados a la carpeta exports.",
    "Reports exported": "Informes exportados",
    "PROFILES AND SCHEDULES": "PERFILES Y PROGRAMACIÓN",
    "Save network groups and automate recurring scans": "Guarda grupos de red y automatiza análisis recurrentes",
    "Saved profile": "Perfil guardado", "LOAD": "CARGAR",
    "SAVE PROFILE": "GUARDAR PERFIL", "SCHEDULE": "PROGRAMAR",
    "No scheduled scans.": "No hay análisis programados.",
    "Delete schedule": "Eliminar programación",
    "Profile name": "Nombre del perfil", "Save scan profile": "Guardar perfil de análisis",
    "Save profile": "Guardar perfil", "Scan profile saved.": "Perfil de análisis guardado.",
    "Save or select a profile before scheduling.": "Guarda o selecciona un perfil antes de programar.",
    "Interval": "Intervalo",
    "Notify only when relevant changes are detected": "Notificar solo cuando se detecten cambios relevantes",
    "Schedule recurring scan": "Programar análisis recurrente",
    "Create schedule": "Crear programación", "Scheduled scan created.": "Análisis programado creado.",
    "NETWORK HEALTH": "SALUD DE LA RED",
    "LOCAL PORT INSPECTOR": "INSPECTOR DE PUERTOS LOCALES",
    "Local ports": "Puertos locales",
    "Processes and services listening on this computer": "Procesos y servicios en escucha en este equipo",
    "LISTENING PORTS": "PUERTOS EN ESCUCHA",
    "NETWORK VISIBLE": "VISIBLES EN RED",
    "REQUIRE ATTENTION": "REQUIEREN ATENCIÓN",
    "Port, process, service or address": "Puerto, proceso, servicio o dirección",
    "Exposure filter": "Filtro de exposición",
    "All listeners": "Todos los puertos",
    "Network visible": "Visibles en red",
    "Require attention": "Requieren atención",
    "Local only": "Solo locales",
    "PORTS OPEN ON THIS COMPUTER": "PUERTOS ABIERTOS EN ESTE EQUIPO",
    "VIEW PORTS": "VER PUERTOS",
    "Read-only inspection": "Inspección de solo lectura",
    "A listening port is not automatically dangerous. Review the process and whether it is visible from the network.": "Un puerto en escucha no es automáticamente peligroso. Revisa el proceso y si es visible desde la red.",
    "No ports match the current filter, or administrator permission is required.": "Ningún puerto coincide con el filtro actual o se requieren permisos de administrador.",
    "Check which ports are listening on this computer.": "Comprueba qué puertos están escuchando en este equipo.",
    "A listening port is not automatically dangerous. Review its process and exposure.": "Un puerto en escucha no es automáticamente peligroso. Revisa su proceso y exposición.",
    "REFRESH": "ACTUALIZAR",
    "UPDATING...": "ACTUALIZANDO...",
    "Not updated yet": "Aún no se ha actualizado",
    "Inspecting local listeners...": "Inspeccionando puertos locales en escucha...",
    "Press Refresh to inspect local ports.": "Pulsa Actualizar para inspeccionar los puertos locales.",
    "This computer only": "Solo este equipo",
    "All network interfaces": "Todas las interfaces de red",
    "Specific network interface": "Interfaz de red específica",
    "No local listening ports were found, or administrator permission is required.": "No se encontraron puertos locales en escucha o se requieren permisos de administrador.",
    "NETWORK HEALTH DETAILS": "DETALLE DE SALUD DE LA RED",
    "Run a scan to calculate network health.": "Ejecuta un análisis para calcular la salud de la red.",
    "No health assessment yet.": "Todavía no hay una evaluación de salud.",
    "No deductions. The scanned network is healthy according to current evidence.": "Sin descuentos. La red analizada está saludable según la evidencia actual.",
    "Device discovery": "Descubrimiento de dispositivos",
    "Global discovery": "Descubrimiento global",
    "Quick ports": "Puertos rápidos",
    "Service inventory": "Inventario de servicios",
    "Deep audit": "Auditoría profunda",
    "Vulnerability audit": "Auditoría de vulnerabilidades",
    "CHANGES ONLY": "SOLO CAMBIOS", "ALWAYS": "SIEMPRE",
    "NEW": "NUEVO", "KNOWN": "CONOCIDO", "AUTHORIZED": "AUTORIZADO",
    "BLOCKED": "BLOQUEADO", "UNKNOWN": "DESCONOCIDO",
    "EXCELLENT": "EXCELENTE", "GOOD": "BUENA", "ATTENTION": "ATENCIÓN",
    "CRITICAL": "CRÍTICA", "RESOLVED": "RESUELTO",
    "HIGH": "ALTO", "MEDIUM": "MEDIO", "LOW": "BAJO",
    "NEW DEVICE": "DISPOSITIVO NUEVO", "MISSING DEVICE": "DISPOSITIVO AUSENTE",
    "IP CHANGED": "IP CAMBIADA", "PORT OPENED": "PUERTO ABIERTO",
    "PORT CLOSED": "PUERTO CERRADO",
    "High-risk exposed services": "Servicios expuestos de riesgo alto",
    "Medium-risk exposed services": "Servicios expuestos de riesgo medio",
    "Unclassified devices": "Dispositivos sin clasificar",
    "Blocked devices online": "Dispositivos bloqueados en línea",
    "Relevant recent changes": "Cambios recientes relevantes",
    "Nmap script findings": "Hallazgos de scripts Nmap",
    "Incomplete scan coverage": "Cobertura de análisis incompleta",
    "INVENTORY": "INVENTARIO", "SERVICE": "SERVICIO",
    "TRAFFIC": "TRÁFICO", "PROCESS": "PROCESO",
    "15 minutes": "15 minutos", "30 minutes": "30 minutos",
    "1 hour": "1 hora", "6 hours": "6 horas", "24 hours": "24 horas",
    "netpulse.db  ·  same folder as main.py": "netpulse.db  ·  carpeta de datos de la aplicación",
    "Direction": "Dirección", "Filter IP": "Filtrar IP", "Pause": "Pausar",
    "Export CSV": "Exportar CSV", "DOWNLOAD": "DESCARGA", "UPLOAD": "SUBIDA",
    "PACKETS/SEC": "PAQUETES/SEG", "BANDWIDTH OVER TIME  ( KB/s )": "ANCHO DE BANDA EN EL TIEMPO  ( KB/s )",
    "PROTOCOL DISTRIBUTION": "DISTRIBUCIÓN DE PROTOCOLOS",
    "Session": "Sesión", "Captured session": "Sesión capturada",
    "Choose a session to review": "Elige una sesión para revisarla",
    "CAPTURED SESSIONS": "SESIONES CAPTURADAS",
    "RELOAD SESSIONS": "RECARGAR SESIONES",
    "Select a session to see its summary": "Selecciona una sesión para ver su resumen",
    "No captured sessions yet": "Todavía no hay sesiones capturadas",
    "HISTORICAL TRAFFIC  ( KB/s per second )": "TRÁFICO HISTÓRICO  ( KB/s por segundo )",
    "PER-PROCESS BANDWIDTH": "ANCHO DE BANDA POR PROCESO",
    "Process": "Proceso", "Bytes": "Bytes", "Share": "Participación",
    "CAPTURE SETTINGS": "AJUSTES DE CAPTURA", "Network Interface": "Interfaz de red",
    "All interfaces": "Todas las interfaces", "TRAFFIC ALERTS": "ALERTAS DE TRÁFICO",
    "Save Alerts": "Guardar alertas", "REQUIREMENTS": "REQUISITOS",
    "Language": "Idioma", "English": "Inglés", "Spanish": "Español",
    "All": "Todos", "Interface": "Interfaz", "Time": "Hora", "Dir": "Dir.",
    "Src IP": "IP origen", "Dst IP": "IP destino", "Port": "Puerto",
    "Remote IP": "IP remota", "Last Seen": "Última actividad",
    "Domain / Geo": "Dominio / Ubicación", "Received": "Recibido", "Sent": "Enviado",
    "Download": "Descarga", "Upload": "Subida", "Resume": "Reanudar",
    "No packets captured yet": "Todavía no se capturaron paquetes",
    "Start capture or generate network traffic.": "Inicia la captura o genera tráfico de red.",
    "No process traffic available": "No hay tráfico de procesos disponible",
    "Start capture to associate connections with applications.": "Inicia la captura para asociar conexiones con aplicaciones.",
    "Run a scan to build the inventory.": "Ejecuta un escaneo para crear el inventario.",
    "No alerts.": "Sin alertas.", "No scans yet": "Aún no hay escaneos",
    "Nmap ready": "Nmap listo", "Nmap not found": "Nmap no encontrado",
    "No relevant changes or exposed high-risk services.": "No hay cambios relevantes ni servicios expuestos de alto riesgo.",
    "No responding devices were found.": "No se encontraron dispositivos que respondan.",
    "No open ports in this scan profile": "No hay puertos abiertos con este perfil",
    "Unidentified device": "Dispositivo no identificado", "Scan cancelled.": "Escaneo cancelado.",
    "Select a captured session…": "Selecciona una sesión capturada…",
    "← select a session": "← selecciona una sesión",
    "TOP CONNECTIONS  ( this session )": "CONEXIONES PRINCIPALES  ( esta sesión )",
    "Changes take effect on the next capture start.": "Los cambios se aplican al iniciar la próxima captura.",
    "Set thresholds to trigger notifications during capture.": "Define umbrales para recibir notificaciones durante la captura.",
    "Bandwidth threshold (KB/s)": "Umbral de ancho de banda (KB/s)",
    "Packet rate threshold (pkt/s)": "Umbral de paquetes (paq/s)",
    "Only aggregated per-second stats are stored. Raw packets are never written to disk.": "Solo se guardan estadísticas agregadas por segundo. Los paquetes sin procesar nunca se escriben en disco.",
    "Npcap installed  →  npcap.com": "Npcap instalado  →  npcap.com",
    "Run as Administrator  →  start_admin.bat": "Ejecutar como administrador  →  start_admin.bat",
    "Internet access for IP Geo-lookup (ip-api.com)": "Acceso a Internet para geolocalización IP (ip-api.com)",
    "Real-time Network Analyzer": "Analizador de red en tiempo real",
    "WAITING FOR TRAFFIC": "ESPERANDO TRÁFICO", "NO DATA": "SIN DATOS",
    "No session": "Sin sesión", "0 packets": "0 paquetes", "0 processes": "0 procesos",
    "200ms refresh": "actualización 200 ms", "No session": "Sin sesión",
    "⚙️  CAPTURE SETTINGS": "⚙️  AJUSTES DE CAPTURA",
    "🔔  TRAFFIC ALERTS": "🔔  ALERTAS DE TRÁFICO",
    "🗄️  DATABASE  ( SQLite )": "🗄️  BASE DE DATOS  ( SQLite )",
    "⚠️  REQUIREMENTS": "⚠️  REQUISITOS",
    "💾 Save Alerts": "💾 Guardar alertas", "📥 Export CSV": "📥 Exportar CSV",
    "⏸ Pause": "⏸ Pausar", "Waiting...": "Esperando...",
    "Waiting for packets...": "Esperando paquetes...",
    "⚡  LIVE PACKET FEED": "⚡  FLUJO DE PAQUETES EN VIVO",
    "🌐  TOP CONNECTIONS": "🌐  CONEXIONES PRINCIPALES",
    "Applications": "Aplicaciones", "REAL-TIME NETWORK OPERATIONS": "OPERACIONES DE RED EN TIEMPO REAL",
    "Nmap inventory, exposed services, changes and risk indicators": "Inventario Nmap, servicios expuestos, cambios e indicadores de riesgo",
    "Active Nmap discovery, risk overview and scan history.": "Descubrimiento Nmap, resumen de riesgos e historial de escaneos.",
    "HOW TO USE ACTIVE DISCOVERY": "CÓMO USAR EL DESCUBRIMIENTO ACTIVO",
    "1. Enter one or more authorized IPs, hostnames or CIDR networks. Separate them with commas, spaces or new lines.": "1. Ingresa una o varias IP, nombres de host o redes CIDR autorizadas. Sepáralas con comas, espacios o saltos de línea.",
    "2. Choose Device discovery for online hosts, Quick ports for a fast inventory, or deeper methods for detailed analysis.": "2. Elige Descubrimiento de dispositivos para ver equipos en línea, Puertos rápidos para un inventario ágil o métodos avanzados para más detalle.",
    "Example: 172.26.4.0/24, 172.26.3.0/24  •  Scan only networks you own or are authorized to assess.": "Ejemplo: 172.26.4.0/24, 172.26.3.0/24  •  Escanea solo redes propias o para las que tengas autorización.",
    "Domain": "Dominio", "Geo": "Ubicación", "Remote": "Remoto",
    "Sport": "Puerto origen", "Dport": "Puerto destino", "OUT": "SALIDA",
    "BW ≥": "ANCHO DE BANDA ≥", "PPS ≥": "PAQ/S ≥", "peak:": "pico:",
    "0 KB total": "0 KB totales", "0 KB/s": "0 KB/s", "0 pkt/s": "0 paq/s",
    "KB total": "KB totales", "MB total": "MB totales", "processes": "procesos",
    "packets": "paquetes", "devices": "dispositivos", "pkts": "paquetes", "pkt": "paq",
    "Completed": "Completado", "Active": "Activa", "Running": "Ejecutando",
    "Could not start capture:": "No se pudo iniciar la captura:",
    "⚠  Error": "⚠  Error", "→ Run as Administrator": "→ Ejecuta como administrador",
    "→ Npcap must be installed  (npcap.com)": "→ Npcap debe estar instalado  (npcap.com)",
    "⚠️ Alerts disabled (set threshold > 0)": "⚠️ Alertas desactivadas (define un umbral > 0)",
    "✅ Alerts active:": "✅ Alertas activas:", "❌ Invalid number": "❌ Número inválido",
    "❌ Export failed:": "❌ Error al exportar:", "✅ Exported": "✅ Exportados",
    "e.g. 1000  (0 = disabled)": "ej. 1000  (0 = desactivado)",
    "e.g. 5000  (0 = disabled)": "ej. 5000  (0 = desactivado)",
    "↓ in  /  ↑ out peak": "↓ entrada  /  ↑ pico de salida",
    "[ None ]": "[ Ninguna ]", "NetPulse — Network Analyzer": "NetPulse — Analizador de red",
}

CATALOGS = {"en": {}, "es": ES}
_language = "en"


def set_language(language: str) -> str:
    global _language
    _language = language if language in CATALOGS else "en"
    return _language


def get_language() -> str:
    return _language


def tr(value: str, language: str | None = None) -> str:
    """Translate one source string; safe for unknown keys and future text."""
    lang = language or _language
    if lang == "en":
        reverse = {translated: source for source, translated in ES.items()}
        exact = reverse.get(value)
        if exact:
            return exact
        reverse_prefixes = {
            "Ejecutando ": "Running ", "Completado en ": "Completed in ",
            "Completado": "Completed", "Activa": "Active", "Sesión #": "Session #",
            "Perfil cargado: ": "Profile loaded: ",
            "Análisis programado: ": "Scheduled scan: ",
            "Análisis programado completado": "Scheduled scan completed",
            "Falló el análisis programado": "Scheduled scan failed",
            "Prioridad: ": "Priority: ", "Motivo: ": "Why: ",
            "Acción recomendada: ": "Recommended action: ",
            "Evidencia: ": "Evidence: ", "Dispositivo: ": "Device: ",
            "Búsqueda global · ": "Global search · ",
            "Inventario del dispositivo · ": "Device inventory · ",
        }
        result = value
        for translated, source in reverse_prefixes.items():
            if result.startswith(translated):
                result = source + result[len(translated):]
                break
        reverse_replacements = (
            (" dispositivos", " devices"), (" dispositivo(s)", " device(s)"),
            (" paquetes", " packets"), (" equipos", " hosts"),
            (" segmentos", " segments"), (" nodos", " nodes"),
            (" hallazgos en ", " findings in "), (" hallazgos", " findings"),
            (" más", " more"),
            (" puertos en escucha", " listening ports"),
            (" visibles en red", " network-visible"),
            (" requieren atención", " require attention"),
            ("selecciona un nodo para filtrar alertas", "select a node to filter alerts"),
            (" activos", " active"), (" resueltos", " resolved"),
            (" cambios", " changes"), (" riesgo ", " risk "),
            (" puntos descontados", " points deducted"),
            ("Cada ", "Every "), (" · próxima ", " · next "),
            ("Detectado ahora", "Detected now"), ("Ya no responde", "No longer responds"),
            (" servicio(s) abierto(s)", " open service(s)"),
            (" de riesgo alto", " high-risk"), (" de riesgo medio", " medium-risk"),
            (" permanecen como nuevos en el inventario", " remain new in inventory"),
            (" dispositivo(s) bloqueado(s) respondieron", " blocked device(s) responded"),
            (" cambio(s) relevante(s) de seguridad", " security-relevant change(s)"),
            (" hallazgo(s) relevante(s) de scripts", " relevant script finding(s)"),
            (" puntos cada uno", " points each"), ("máximo", "maximum"),
            ("Nuevo puerto abierto ", "New open port "),
            ("Nuevo dispositivo detectado", "New device detected"),
            ("Dispositivo ya no detectado", "Device no longer detected"),
            ("Servicio modificado en ", "Service changed on "),
            ("Puerto cerrado ", "Port closed "),
            ("BUENA", "GOOD"), ("EXCELENTE", "EXCELLENT"),
            ("ATENCIÓN", "ATTENTION"), ("CRÍTICA", "CRITICAL"),
        )
        for translated, source in reverse_replacements:
            result = result.replace(translated, source)
        return result
    exact = CATALOGS.get(lang, {}).get(value)
    if exact:
        return exact
    # Runtime messages keep their numeric or device-specific suffix.
    prefixes = {
        "Running ": "Ejecutando ", "Completed in ": "Completado en ",
        "Completed": "Completado", "Active": "Activa",
        "Session #": "Sesión #", "No session": "Sin sesión",
        "Profile loaded: ": "Perfil cargado: ",
        "Scheduled scan: ": "Análisis programado: ",
        "Scheduled scan completed": "Análisis programado completado",
        "Scheduled scan failed": "Falló el análisis programado",
        "Priority: ": "Prioridad: ",
        "Why: ": "Motivo: ",
        "Recommended action: ": "Acción recomendada: ",
        "Evidence: ": "Evidencia: ",
        "Device: ": "Dispositivo: ",
        "Global search · ": "Búsqueda global · ",
        "Device inventory · ": "Inventario del dispositivo · ",
        "Showing ": "Mostrando ",
        "Updated at ": "Actualizado a las ",
        "Update failed: ": "Falló la actualización: ",
    }
    for source, translated in prefixes.items():
        if value.startswith(source):
            result = translated + value[len(source):]
            value = result
            break
    replacements = (
        (" devices", " dispositivos"), (" device(s)", " dispositivo(s)"),
        (" packets", " paquetes"), (" sessions", " sesiones"), (" hosts", " equipos"),
        (" segments", " segmentos"), (" nodes", " nodos"),
        (" findings in ", " hallazgos en "), (" findings", " hallazgos"),
        (" more", " más"),
        (" listening ports", " puertos en escucha"),
        (" network-visible", " visibles en red"),
        (" require attention", " requieren atención"),
        (" of ", " de "),
        (" ports. Use search or filters to narrow the list.",
         " puertos. Usa la búsqueda o los filtros para reducir la lista."),
        ("select a node to filter alerts", "selecciona un nodo para filtrar alertas"),
        (" active", " activos"), (" resolved", " resueltos"),
        (" relevant changes", " cambios relevantes"),
        (" changes", " cambios"), (" risk ", " riesgo "),
        (" points deducted", " puntos descontados"),
        ("Every ", "Cada "), (" min · ", " min · "), (" · next ", " · próxima "),
        ("Detected now", "Detectado ahora"),
        ("No longer responds", "Ya no responde"),
        (" open service(s)", " servicio(s) abierto(s)"),
        (" high-risk", " de riesgo alto"), (" medium-risk", " de riesgo medio"),
        (" remain new in inventory", " permanecen como nuevos en el inventario"),
        (" blocked device(s) responded", " dispositivo(s) bloqueado(s) respondieron"),
        (" security-relevant change(s)", " cambio(s) relevante(s) de seguridad"),
        (" relevant script finding(s)", " hallazgo(s) relevante(s) de scripts"),
        (" points each", " puntos cada uno"), ("maximum", "máximo"),
        ("Some discovered devices were not port-scanned; the result has incomplete coverage.",
         "Algunos dispositivos descubiertos no fueron analizados por puertos; el resultado tiene cobertura incompleta."),
        ("New open port ", "Nuevo puerto abierto "),
        ("New device detected", "Nuevo dispositivo detectado"),
        ("Device no longer detected", "Dispositivo ya no detectado"),
        ("Service changed on ", "Servicio modificado en "),
        ("Port closed ", "Puerto cerrado "),
        ("GOOD", "BUENA"), ("EXCELLENT", "EXCELENTE"),
        ("ATTENTION", "ATENCIÓN"), ("CRITICAL", "CRÍTICA"),
    )
    result = value
    for source, translated in replacements:
        result = result.replace(source, translated)
    return result


def _translate(value: str, language: str) -> str:
    return tr(value, language)


def translate_tree(control, language: str, seen=None) -> None:
    """Translate common textual properties recursively without rebuilding views."""
    if control is None:
        return
    seen = seen or set()
    if id(control) in seen:
        return
    seen.add(id(control))
    for attr in ("value", "label", "hint_text", "content", "text", "tooltip", "error_text"):
        value = getattr(control, attr, None)
        if isinstance(value, str):
            setattr(control, attr, _translate(value, language))
    for attr in (
        "content", "controls", "destinations", "options", "leading", "trailing",
        "icon", "selected_icon", "title", "subtitle", "actions",
    ):
        child = getattr(control, attr, None)
        if isinstance(child, (list, tuple)):
            for item in child:
                translate_tree(item, language, seen)
        elif isinstance(child, ft.Control):
            translate_tree(child, language, seen)
