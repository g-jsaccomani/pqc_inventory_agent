"""Saves assessment reports written by the Gemini agents (Markdown + print-ready HTML, local disk and GCS).

The report CONTENT is authored entirely by the LLM (report_writer_agent). This module only renders the Markdown
into the Google Cloud Consulting HTML layout, writes the files, uploads them to Cloud Storage when configured and
registers them as session artifacts. It contains no report templates or pre-written findings.
"""

from __future__ import annotations

import datetime
import html
import json
import logging
import os
import pathlib
import re
from typing import Any, Dict, List, Optional

from google.genai import types

logger = logging.getLogger(__name__)


def _markdown_to_html_body(md_text: str) -> str:
    """Lightweight, zero-dependency Markdown-to-HTML converter for tables, code blocks, headers, and lists."""
    lines = md_text.splitlines()
    html_out: List[str] = []
    in_code_block = False
    code_lang = ""
    code_lines: List[str] = []
    in_table = False
    table_header_done = False
    in_list = False

    def _format_inline(text: str) -> str:
        # Preserve <br/> tags while escaping HTML
        parts = text.split("<br/>")
        escaped_parts = []
        for p in parts:
            esc = html.escape(p)
            # Bold **...**
            esc = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", esc)
            # Italic *...*
            esc = re.sub(r"\*(.+?)\*", r"<em>\1</em>", esc)
            # Inline code `...`
            esc = re.sub(r"`([^`]+)`", r"<code>\1</code>", esc)
            escaped_parts.append(esc)
        return "<br/>".join(escaped_parts)

    for raw_line in lines:
        stripped = raw_line.strip()

        if stripped.startswith("```"):
            if in_table:
                html_out.append("</tbody></table></div>")
                in_table = False
                table_header_done = False
            if in_list:
                html_out.append("</ul>")
                in_list = False
            if not in_code_block:
                in_code_block = True
                code_lang = stripped[3:].strip() or "text"
                code_lines = []
            else:
                in_code_block = False
                escaped_code = html.escape("\n".join(code_lines))
                html_out.append(
                    f'<div class="code-container"><div class="code-lang">{html.escape(code_lang.upper())}</div>'
                    f"<pre><code>{escaped_code}</code></pre></div>"
                )
            continue

        if in_code_block:
            code_lines.append(raw_line)
            continue

        # Table rows
        if stripped.startswith("|") and stripped.endswith("|"):
            if in_list:
                html_out.append("</ul>")
                in_list = False
            cols = [c.strip() for c in stripped.strip("|").split("|")]
            # Check if separator row like | :--- | :---: |
            if all(re.match(r"^:?-{2,}:?$", c) for c in cols):
                continue
            if not in_table:
                html_out.append('<div class="table-wrap"><table><thead><tr>')
                for c in cols:
                    html_out.append(f"<th>{_format_inline(c)}</th>")
                html_out.append("</tr></thead><tbody>")
                in_table = True
                table_header_done = True
            else:
                html_out.append("<tr>")
                for c in cols:
                    html_out.append(f"<td>{_format_inline(c)}</td>")
                html_out.append("</tr>")
            continue
        elif in_table:
            html_out.append("</tbody></table></div>")
            in_table = False
            table_header_done = False

        if stripped == "---":
            if in_list:
                html_out.append("</ul>")
                in_list = False
            html_out.append("<hr/>")
            continue

        if not stripped:
            if in_list:
                html_out.append("</ul>")
                in_list = False
            continue

        # Headings
        if stripped.startswith("# "):
            html_out.append(f"<h1>{_format_inline(stripped[2:])}</h1>")
        elif stripped.startswith("## "):
            html_out.append(f"<h2>{_format_inline(stripped[3:])}</h2>")
        elif stripped.startswith("### "):
            html_out.append(f"<h3>{_format_inline(stripped[4:])}</h3>")
        elif stripped.startswith("#### "):
            html_out.append(f"<h4>{_format_inline(stripped[5:])}</h4>")
        elif stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                html_out.append("<ul>")
                in_list = True
            item_text = stripped[2:].strip()
            if item_text.startswith("[ ] "):
                item_text = "&#9744; " + _format_inline(item_text[4:])
            elif item_text.startswith("[x] ") or item_text.startswith("[X] "):
                item_text = "&#9745; " + _format_inline(item_text[4:])
            else:
                item_text = _format_inline(item_text)
            html_out.append(f"<li>{item_text}</li>")
        else:
            if in_list:
                html_out.append("</ul>")
                in_list = False
            html_out.append(f"<p>{_format_inline(stripped)}</p>")

    if in_table:
        html_out.append("</tbody></table></div>")
    if in_list:
        html_out.append("</ul>")
    return "\n".join(html_out)


def render_styled_consulting_html(
    markdown_text: str,
    title: str = "Google Cloud Consulting — PQC Readiness Deliverable",
    badge_label: str = "GOOGLE CLOUD CONSULTING • POST-QUANTUM CRYPTOGRAPHY",
) -> str:
    """Renders a Markdown report into a print-to-PDF ready Google Cloud Consulting HTML document."""
    body_html = _markdown_to_html_body(markdown_text)
    generated_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      --gcp-blue: #1a73e8;
      --gcp-dark: #202124;
      --gcp-gray: #5f6368;
      --gcp-light-bg: #f8f9fa;
      --gcp-border: #dadce0;
      --gcp-green: #1e8e3e;
      --gcp-red: #d93025;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Google Sans", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: var(--gcp-dark);
      background: #ffffff;
      line-height: 1.6;
      margin: 0;
      padding: 0;
    }}
    .page-wrapper {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 40px 48px;
    }}
    .top-banner {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 3px solid var(--gcp-blue);
      padding-bottom: 14px;
      margin-bottom: 28px;
    }}
    .top-banner .brand {{
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 1.2px;
      color: var(--gcp-blue);
      text-transform: uppercase;
    }}
    .top-banner .timestamp {{
      font-size: 12px;
      color: var(--gcp-gray);
    }}
    h1 {{
      font-size: 26px;
      color: var(--gcp-blue);
      margin: 0 0 6px 0;
      letter-spacing: -0.3px;
    }}
    h2 {{
      font-size: 20px;
      color: var(--gcp-dark);
      margin-top: 32px;
      margin-bottom: 12px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--gcp-border);
    }}
    h3 {{
      font-size: 16px;
      color: #174ea6;
      margin-top: 24px;
      margin-bottom: 8px;
    }}
    h4 {{
      font-size: 14px;
      color: var(--gcp-dark);
      background: var(--gcp-light-bg);
      padding: 8px 12px;
      border-left: 4px solid var(--gcp-blue);
      margin-top: 20px;
      margin-bottom: 8px;
    }}
    p, li {{
      font-size: 14px;
      color: #3c4043;
    }}
    ul {{
      margin: 8px 0 16px 20px;
      padding: 0;
    }}
    li {{
      margin-bottom: 6px;
    }}
    hr {{
      border: 0;
      border-top: 1px solid var(--gcp-border);
      margin: 28px 0;
    }}
    .table-wrap {{
      overflow-x: auto;
      margin: 14px 0 22px 0;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      border: 1px solid var(--gcp-border);
    }}
    th {{
      background: #e8f0fe;
      color: #174ea6;
      font-weight: 600;
      text-align: left;
      padding: 10px 12px;
      border: 1px solid var(--gcp-border);
    }}
    td {{
      padding: 9px 12px;
      border: 1px solid var(--gcp-border);
      vertical-align: top;
    }}
    tr:nth-child(even) td {{
      background: #fbfcfe;
    }}
    code {{
      font-family: "Roboto Mono", "SFMono-Regular", Consolas, Menlo, monospace;
      font-size: 12px;
      background: #f1f3f4;
      color: #c5221f;
      padding: 2px 5px;
      border-radius: 4px;
      word-break: break-word;
    }}
    .code-container {{
      margin: 12px 0 20px 0;
      border: 1px solid var(--gcp-border);
      border-radius: 6px;
      overflow: hidden;
      background: #1e1e1e;
    }}
    .code-lang {{
      background: #2d2d2d;
      color: #9aa0a6;
      font-size: 11px;
      font-weight: 600;
      padding: 5px 12px;
      font-family: monospace;
    }}
    pre {{
      margin: 0;
      padding: 14px;
      overflow-x: auto;
    }}
    pre code {{
      background: transparent;
      color: #e8eaed;
      padding: 0;
      font-size: 12px;
      word-break: normal;
    }}
    @media print {{
      .page-wrapper {{ padding: 15px 20px; max-width: 100%; }}
      h2, h3, h4 {{ page-break-after: avoid; }}
      .table-wrap, .code-container {{ page-break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <div class="page-wrapper">
    <div class="top-banner">
      <div class="brand">{html.escape(badge_label)}</div>
      <div class="timestamp">Generated: {generated_ts}</div>
    </div>
    {body_html}
  </div>
</body>
</html>
"""


def _upload_files_to_gcs(
    local_files: Dict[str, pathlib.Path],
    gcs_bucket_uri: str,
    scope_slug: str,
) -> Dict[str, Any]:
    """Uploads exported files to Google Cloud Storage (`gs://...`) if configured and reachable."""
    bucket_clean = gcs_bucket_uri.strip()
    if bucket_clean.startswith("gs://"):
        bucket_clean = bucket_clean[5:]
    bucket_name = bucket_clean.split("/", 1)[0].strip()
    prefix_base = bucket_clean.split("/", 1)[1].strip("/") if "/" in bucket_clean else "pqc-reports"
    ts_slug = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    folder_prefix = f"{prefix_base}/{scope_slug}-{ts_slug}"

    try:
        from google.cloud import storage  # type: ignore

        client = storage.Client()
        bucket = client.bucket(bucket_name)
        uploaded: List[Dict[str, str]] = []
        for label, fpath in local_files.items():
            blob_path = f"{folder_prefix}/{fpath.name}"
            blob = bucket.blob(blob_path)
            content_type = (
                "text/html; charset=utf-8"
                if fpath.suffix == ".html"
                else ("application/json" if fpath.suffix == ".json" else "text/markdown; charset=utf-8")
            )
            blob.upload_from_filename(str(fpath), content_type=content_type)
            uploaded.append(
                {
                    "deliverable": label,
                    "filename": fpath.name,
                    "gcs_uri": f"gs://{bucket_name}/{blob_path}",
                    "cloud_console_url": f"https://console.cloud.google.com/storage/browser/_details/{bucket_name}/{blob_path}",
                }
            )
        return {
            "gcs_upload_status": "UPLOADED_TO_GCS",
            "gcs_folder_uri": f"gs://{bucket_name}/{folder_prefix}/",
            "gcs_console_folder_url": f"https://console.cloud.google.com/storage/browser/{bucket_name}/{folder_prefix}",
            "uploaded_artifacts": uploaded,
        }
    except Exception as exc:
        logger.warning("GCS upload skipped or failed for bucket '%s': %s", gcs_bucket_uri, exc)
        return {
            "gcs_upload_status": "LOCAL_EXPORT_ONLY",
            "gcs_note": f"Files written locally; GCS upload skipped ({exc}).",
        }



def _slug(text: str, max_len: int = 60) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", (text or "").strip()).strip("-").lower()
    return (cleaned or "report")[:max_len]


def _default_output_dir() -> pathlib.Path:
    if os.path.isdir("/data") and os.access("/data", os.W_OK):
        return pathlib.Path("/data/exports")
    return pathlib.Path(os.getenv("PQC_EXPORT_DIR", "exports"))


async def save_assessment_report(
    report_title: str,
    report_markdown: str,
    report_type: str = "assessment",
    scope: str = "",
    tool_context: Any = None,
) -> str:
    """Saves a report written by the agent as Markdown and print-ready HTML (local, Cloud Storage, session artifacts).

    The agent must pass the complete report content in `report_markdown`; nothing is added or generated here.

    Args:
        report_title: Title shown on the HTML cover (e.g. 'PQC Readiness Assessment - Executive Report').
        report_markdown: Full report content in Markdown, written by the agent.
        report_type: Short label such as 'executive', 'technical' or 'assessment' (used in file names).
        scope: Assessed scope (e.g. 'organizations/<id>'), used for the storage folder name.

    Returns:
        JSON with local file paths, Cloud Storage URIs (when uploaded) and session artifact names.
    """
    content = (report_markdown or "").strip()
    if len(content) < 40:
        return json.dumps(
            {"status": "REJECTED", "reason": "report_markdown is empty or too short; pass the full report content."},
            ensure_ascii=False,
        )

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    base_name = f"{ts}_{_slug(report_type, 24)}_{_slug(report_title)}"
    out_dir = _default_output_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / f"{base_name}.md"
    html_path = out_dir / f"{base_name}.html"
    md_path.write_text(content + "\n", encoding="utf-8")
    html_path.write_text(render_styled_consulting_html(content, title=report_title), encoding="utf-8")

    result: Dict[str, Any] = {
        "status": "SAVED",
        "report_title": report_title,
        "report_type": report_type,
        "authored_by": "LLM agent (report content passed verbatim)",
        "local_files": {"markdown": str(md_path), "html": str(html_path)},
    }

    bucket = os.getenv("PQC_ARTIFACT_BUCKET") or os.getenv("PQC_EXPORT_GCS_BUCKET") or ""
    if bucket:
        result["cloud_storage"] = _upload_files_to_gcs(
            {"markdown": md_path, "html": html_path}, bucket, _slug(scope or "scope", 40)
        )

    if tool_context is not None:
        saved: List[str] = []
        try:
            await tool_context.save_artifact(md_path.name, types.Part.from_text(text=content))
            saved.append(md_path.name)
            await tool_context.save_artifact(
                html_path.name,
                types.Part.from_bytes(data=html_path.read_bytes(), mime_type="text/html"),
            )
            saved.append(html_path.name)
        except Exception as exc:
            result["session_artifact_error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
        result["session_artifacts"] = saved

    return json.dumps(result, ensure_ascii=False)
