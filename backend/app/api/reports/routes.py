"""POST /api/reports/generate — AI-generated threat report endpoint."""

import io
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request
from flask_jwt_extended import jwt_required

from app.api.reports.chain import generate_report

reports_bp = Blueprint("reports", __name__)


def _markdown_to_pdf(markdown_text: str) -> bytes:
    """Convert a markdown string to PDF bytes via xhtml2pdf."""
    import markdown as md_lib
    from xhtml2pdf import pisa

    html_body = md_lib.markdown(
        markdown_text,
        extensions=["tables", "fenced_code"],
    )
    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <style>
    @page {{ margin: 2cm; }}
    body {{ font-family: Arial, sans-serif; font-size: 11pt; color: #1a1a1a; }}
    h1 {{ font-size: 20pt; color: #1a1a2e; border-bottom: 2px solid #c0392b; padding-bottom: 6px; }}
    h2 {{ font-size: 15pt; color: #16213e; margin-top: 24px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }}
    h3 {{ font-size: 12pt; color: #0f3460; margin-top: 16px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
    th {{ background: #1a1a2e; color: white; padding: 6px 10px; text-align: left; }}
    td {{ padding: 5px 10px; border-bottom: 1px solid #ddd; }}
    tr:nth-child(even) {{ background: #f7f7f7; }}
    code {{ background: #f4f4f4; padding: 1px 4px; font-size: 10pt; }}
    pre {{ background: #f4f4f4; padding: 10px; }}
    ul, ol {{ margin: 8px 0; padding-left: 24px; }}
  </style>
</head>
<body>{html_body}</body>
</html>"""

    buf = io.BytesIO()
    pisa.CreatePDF(io.StringIO(html), dest=buf)
    return buf.getvalue()


@reports_bp.route("/api/reports/generate", methods=["POST"])
@jwt_required()
def generate_threat_report():
    """Generate a structured security report from the last N detections.

    Request body (JSON, all optional):
      n      — number of detections to analyse (default 100, max 500)
      format — "markdown" | "pdf"  (default "markdown")

    Returns:
      markdown: JSON with {markdown, stats, generated_at, n_detections}
      pdf:      binary PDF attachment
    """
    body = request.get_json(silent=True) or {}
    n = min(int(body.get("n", 100)), 500)
    fmt = str(body.get("format", "markdown")).lower()

    try:
        result = generate_report(n=n)
    except Exception as exc:
        return jsonify({"error": f"Report generation failed: {exc}"}), 500

    if fmt == "pdf":
        try:
            pdf_bytes = _markdown_to_pdf(result["markdown"])
        except Exception as exc:
            return jsonify({"error": f"PDF conversion failed: {exc}. Use format=markdown instead."}), 500

        filename = f"threat_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    return jsonify({
        "markdown": result["markdown"],
        "stats": result["stats"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_detections": n,
    })
