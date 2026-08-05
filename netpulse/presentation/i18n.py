"""NetPulse internationalization engine.

English source strings are stable translation keys. Add a language by creating
one catalog and registering it in ``CATALOGS``; views do not need rebuilding.
"""

import flet as ft


ES = {
    "Overview": "Resumen", "Network": "Red", "Packets": "Paquetes",
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
    "Direction": "Dirección", "Filter IP": "Filtrar IP", "Pause": "Pausar",
    "Export CSV": "Exportar CSV", "DOWNLOAD": "DESCARGA", "UPLOAD": "SUBIDA",
    "PACKETS/SEC": "PAQUETES/SEG", "BANDWIDTH OVER TIME  ( KB/s )": "ANCHO DE BANDA EN EL TIEMPO  ( KB/s )",
    "PROTOCOL DISTRIBUTION": "DISTRIBUCIÓN DE PROTOCOLOS",
    "Session": "Sesión", "HISTORICAL TRAFFIC  ( KB/s per second )": "TRÁFICO HISTÓRICO  ( KB/s por segundo )",
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
        }
        result = value
        for translated, source in reverse_prefixes.items():
            if result.startswith(translated):
                result = source + result[len(translated):]
                break
        return result.replace(" dispositivos", " devices").replace(" paquetes", " packets")
    exact = CATALOGS.get(lang, {}).get(value)
    if exact:
        return exact
    # Runtime messages keep their numeric or device-specific suffix.
    prefixes = {
        "Running ": "Ejecutando ", "Completed in ": "Completado en ",
        "Completed": "Completado", "Active": "Activa",
        "Session #": "Sesión #", "No session": "Sin sesión",
    }
    for source, translated in prefixes.items():
        if value.startswith(source):
            result = translated + value[len(source):]
            return result.replace(" devices", " dispositivos").replace(" packets", " paquetes")
    return value


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
    for attr in ("value", "label", "hint_text", "content", "text"):
        value = getattr(control, attr, None)
        if isinstance(value, str):
            setattr(control, attr, _translate(value, language))
    for attr in ("content", "controls", "destinations", "options", "leading", "trailing", "icon", "selected_icon"):
        child = getattr(control, attr, None)
        if isinstance(child, (list, tuple)):
            for item in child:
                translate_tree(item, language, seen)
        elif isinstance(child, ft.Control):
            translate_tree(child, language, seen)
