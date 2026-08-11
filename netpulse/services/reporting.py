"""Export consistent network scan reports to PDF, HTML and CSV."""

from __future__ import annotations

import csv
from datetime import datetime
from html import escape
from pathlib import Path

from netpulse.domain.comparison import compare_scan_details
from netpulse.domain.diagnostics import build_diagnostics
from netpulse.domain.network_scan import NetworkScan
from netpulse.domain.health import calculate_network_health


def export_scan_reports(
    scan: NetworkScan,
    previous: NetworkScan | None,
    inventory: list[dict],
    output_dir: str | Path,
) -> dict[str, Path]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    stamp = scan.started_at.strftime("%Y%m%d_%H%M%S")
    base = output / f"netpulse_scan_{scan.scan_id or 'actual'}_{stamp}"
    paths = {kind: base.with_suffix(f".{kind}") for kind in ("pdf", "html", "csv")}
    _write_csv(paths["csv"], scan, inventory)
    _write_html(paths["html"], scan, previous, inventory)
    _write_pdf(paths["pdf"], scan, previous, inventory)
    return paths


def _inventory_by_address(inventory: list[dict]) -> dict[str, dict]:
    return {item.get("address", ""): item for item in inventory}


def _inventory_for_host(host, inventory: list[dict], by_ip: dict[str, dict]) -> dict:
    if getattr(host, "device_id", None):
        item = next((entry for entry in inventory
                     if entry.get("device_id") == host.device_id
                     or host.device_id in entry.get("merged_device_ids", [])), None)
        if item:
            return item
    return by_ip.get(host.address, {})


def _write_csv(path: Path, scan: NetworkScan, inventory: list[dict]) -> None:
    by_ip = _inventory_by_address(inventory)
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.writer(stream)
        writer.writerow([
            "asset_id", "ip", "mac", "hostname", "alias", "tipo", "propietario",
            "ubicacion", "confianza", "ciclo_vida", "criticidad", "confianza_identidad", "etiquetas",
            "riesgo", "puerto", "protocolo", "servicio", "producto", "version",
        ])
        for host in scan.hosts:
            item = _inventory_for_host(host, inventory, by_ip)
            services = host.open_ports or [None]
            for service in services:
                writer.writerow([
                    item.get("device_id", host.device_id or ""), host.address, host.mac,
                    host.hostname, item.get("alias", ""),
                    item.get("device_type", ""), item.get("owner", ""),
                    item.get("location", ""), item.get("trust_status", "new"),
                    item.get("lifecycle_status", item.get("trust_status", "new")),
                    item.get("criticality", "medium"), item.get("identity_confidence", "low"),
                    item.get("tags", ""),
                    host.risk_level, service.port if service else "",
                    service.protocol if service else "", service.name if service else "",
                    service.product if service else "", service.version if service else "",
                ])


def _write_html(
    path: Path, scan: NetworkScan, previous: NetworkScan | None, inventory: list[dict]
) -> None:
    diagnostics = build_diagnostics(previous, scan)
    comparison = compare_scan_details(previous, scan)
    health = calculate_network_health(scan, inventory)
    by_ip = _inventory_by_address(inventory)
    rows = []
    for host in scan.hosts:
        item = _inventory_for_host(host, inventory, by_ip)
        ports = ", ".join(f"{s.port}/{s.protocol} {s.name}" for s in host.open_ports) or "Sin puertos abiertos"
        rows.append(
            f"<tr><td><code>{escape(host.address)}</code></td><td>{escape(item.get('alias') or host.hostname or '-')}</td>"
            f"<td>{escape(item.get('lifecycle_status', item.get('trust_status', 'new')))}</td><td class='{escape(host.risk_level)}'>{escape(host.risk_level.upper())}</td>"
            f"<td>{escape(ports)}</td></tr>"
        )
    diagnostic_rows = "".join(
        f"<article class='finding {escape(item.severity)}'><b>{escape(item.host)} - {escape(item.title)}</b>"
        f"<p><strong>Motivo:</strong> {escape(item.why)}</p>"
        f"<p><strong>Accion:</strong> {escape(item.recommendation)}</p>"
        f"<small>Evidencia: {escape(item.evidence or '-')}</small></article>"
        for item in diagnostics.items
    ) or "<p class='ok'>No se detectaron problemas activos ni resueltos recientemente.</p>"
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    html = f"""<!doctype html><html lang='es'><head><meta charset='utf-8'>
<title>Informe NetPulse - {escape(scan.target)}</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#07101d;color:#eaf6ff}}
main{{max-width:1100px;margin:auto;padding:32px}}h1,h2{{color:#00d4ff}}code{{color:#00d4ff}}
.meta,.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.card,.finding{{background:#0d1728;border:1px solid #1a3048;border-radius:10px;padding:14px}}
.metric{{font-size:28px;font-weight:700}}table{{width:100%;border-collapse:collapse;background:#0d1728}}th,td{{padding:10px;border-bottom:1px solid #1a3048;text-align:left}}
.high{{color:#ff4558}}.medium{{color:#ffb820}}.low,.ok{{color:#00ff88}}small{{color:#91a9ba}}
@media print{{body{{background:white;color:#111}}.card,.finding,table{{background:white}}}}
</style></head><body><main><h1>NetPulse - Informe de red</h1>
<p>Objetivo: <code>{escape(scan.target)}</code> | Analisis #{scan.scan_id or '-'} | Generado {generated}</p>
<section class='grid'><div class='card'><small>Dispositivos</small><div class='metric'>{len(scan.hosts)}</div></div>
<div class='card'><small>Puertos abiertos</small><div class='metric'>{scan.open_port_count}</div></div>
<div class='card'><small>Salud</small><div class='metric {scan.risk_level}'>{health.score}/100</div></div>
<div class='card'><small>Cambios</small><div class='metric'>{comparison.total_changes}</div></div></section>
<h2>Resumen ejecutivo</h2><p>Se analizaron {len(scan.hosts)} dispositivos. La salud es {health.score}/100 ({escape(health.level)}). Hay {diagnostics.active_issues} problemas activos y {diagnostics.resolved_issues} resueltos.</p>
<h2>Factores de salud</h2>{''.join(f"<p><strong>-{factor.deduction} {escape(factor.label)}:</strong> {escape(factor.explanation)}</p>" for factor in health.factors) or "<p class='ok'>Sin descuentos de salud.</p>"}
<h2>Inventario y servicios</h2><table><thead><tr><th>IP</th><th>Nombre</th><th>Confianza</th><th>Riesgo</th><th>Servicios</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<h2>Diagnostico y recomendaciones</h2>{diagnostic_rows}
<h2>Evidencia tecnica</h2><p>Perfil: {escape(scan.profile)} | Nmap {escape(scan.nmap_version or '?')} | Duracion: {scan.duration_seconds:.1f}s</p>
</main></body></html>"""
    path.write_text(html, encoding="utf-8")


def _write_pdf(
    path: Path, scan: NetworkScan, previous: NetworkScan | None, inventory: list[dict]
) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("PDF export requires reportlab. Reinstall requirements.txt.") from exc

    diagnostics = build_diagnostics(previous, scan)
    health = calculate_network_health(scan, inventory)
    by_ip = _inventory_by_address(inventory)
    navy, cyan, muted = colors.HexColor("#0D1728"), colors.HexColor("#00A8CC"), colors.HexColor("#526779")
    styles = getSampleStyleSheet()
    title = ParagraphStyle("NetPulseTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                           fontSize=22, leading=26, textColor=navy, alignment=TA_LEFT, spaceAfter=5*mm)
    heading = ParagraphStyle("NetPulseHeading", parent=styles["Heading2"], fontName="Helvetica-Bold",
                             fontSize=13, leading=16, textColor=cyan, spaceBefore=4*mm, spaceAfter=2*mm)
    body = ParagraphStyle("NetPulseBody", parent=styles["BodyText"], fontSize=8.5, leading=12,
                          textColor=navy)
    small = ParagraphStyle("NetPulseSmall", parent=body, fontSize=7.5, leading=10, textColor=muted)

    def footer(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#D8E4EC")); canvas.line(18*mm, 14*mm, 192*mm, 14*mm)
        canvas.setFont("Helvetica", 7); canvas.setFillColor(muted)
        canvas.drawString(18*mm, 9*mm, f"NetPulse | Analisis #{scan.scan_id or '-'} | {scan.target}")
        canvas.drawRightString(192*mm, 9*mm, f"Página {document.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=16*mm, bottomMargin=20*mm, title="Informe NetPulse")
    story = [Paragraph("NetPulse - Informe de red", title),
             Paragraph(f"Objetivo: <b>{escape(scan.target)}</b><br/>Fecha: {scan.started_at:%Y-%m-%d %H:%M} | Perfil: {escape(scan.profile)}", body),
             Spacer(1, 4*mm)]
    metrics = [["DISPOSITIVOS", "PUERTOS ABIERTOS", "SALUD", "PROBLEMAS ACTIVOS"],
               [str(len(scan.hosts)), str(scan.open_port_count), f"{health.score}/100", str(diagnostics.active_issues)]]
    table = Table(metrics, colWidths=[43.5*mm]*4, rowHeights=[8*mm, 12*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#F2F7FA")), ("BOX", (0,0), (-1,-1), .5, colors.HexColor("#C7D7E2")),
        ("INNERGRID", (0,0), (-1,-1), .35, colors.HexColor("#D8E4EC")), ("TEXTCOLOR", (0,0), (-1,0), muted),
        ("TEXTCOLOR", (0,1), (-1,1), navy), ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTNAME", (0,1), (-1,1), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,0), 7),
        ("FONTSIZE", (0,1), (-1,1), 15), ("ALIGN", (0,0), (-1,-1), "CENTER"), ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ])); story += [table, Paragraph("Resumen ejecutivo", heading),
                    Paragraph(f"Se analizaron <b>{len(scan.hosts)}</b> dispositivos. La salud es <b>{health.score}/100 ({health.level.upper()})</b>. Se identificaron <b>{diagnostics.active_issues}</b> problemas activos y <b>{diagnostics.resolved_issues}</b> resueltos.", body),
                    Paragraph("Factores de salud", heading)]
    if health.factors:
        for factor in health.factors:
            story.append(Paragraph(
                f"<b>-{factor.deduction} {escape(factor.label)}:</b> {escape(factor.explanation)}", body
            ))
    else:
        story.append(Paragraph("Sin descuentos de salud según la evidencia actual.", body))
    story += [
                    Paragraph("Inventario y servicios", heading)]
    data = [["IP", "Nombre", "Confianza", "Riesgo", "Servicios abiertos"]]
    for host in scan.hosts:
        item = _inventory_for_host(host, inventory, by_ip)
        ports = ", ".join(f"{s.port}/{s.protocol} {s.name}" for s in host.open_ports) or "Ninguno"
        data.append([Paragraph(escape(host.address), small), Paragraph(escape(item.get("alias") or host.hostname or "-"), small),
                     Paragraph(escape(item.get("lifecycle_status", item.get("trust_status", "new"))), small), host.risk_level.upper(), Paragraph(escape(ports), small)])
    inventory_table = Table(data, colWidths=[27*mm, 35*mm, 24*mm, 18*mm, 70*mm], repeatRows=1)
    inventory_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), navy), ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,0), 7),
        ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#C7D7E2")), ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F7FAFC")]), ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4), ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ])); story.append(inventory_table); story.append(Paragraph("Diagnóstico y recomendaciones", heading))
    if not diagnostics.items:
        story.append(Paragraph("No se detectaron problemas activos ni resueltos recientemente.", body))
    for item in diagnostics.items:
        status = "RESUELTO" if item.status == "resolved" else item.severity.upper()
        story += [Paragraph(f"{escape(item.host)} - {escape(item.title)} [{status}]", heading),
                  Paragraph(f"<b>Motivo:</b> {escape(item.why)}", body),
                  Paragraph(f"<b>Acción recomendada:</b> {escape(item.recommendation)}", body),
                  Paragraph(f"<b>Evidencia:</b> {escape(item.evidence or '-')}", small)]
    story += [Paragraph("Evidencia tecnica", heading),
              Paragraph(f"Nmap {escape(scan.nmap_version or '?')} | Duración {scan.duration_seconds:.1f}s | Comando: {escape(scan.command or '-')}", small)]
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
