#!/usr/bin/env python3
"""
Rebuilds all PQC Google Docs and Google Slides in the Drive folder
`PSO Accelerator - Post-Quantum Cryptography (PQC)` (1VN0-Lt766Tm36JRNj74LnsAy8h8MwBb0)
using the official Google Cloud templates requested by the user:
  1. Official Cloudstyle Google Docs Template:
     1x9L5sz5V0CpbEoo_4jl5wQm7l9PlyHADrzXpnODWtbQ
  2. Official Google Cloud 2026 Playbook Google Slides Template:
     1Afld8EjwWm2H9hTxE82vg_kAzoFANMYNkjNsQrdQdKg

Anti-Overlap & Anti-Hallucination Safeguards:
  - In Google Docs:
    * Keeps Page 1 Cover (Header Google Cloud logo `i.5`, 2-line 34pt Google Sans Title,
      14pt Google Sans Subtitle, Cover Illustration `i.0`, and Footer 4-color bar).
    * Deletes template body elements [9..43] (indices 69..4283), which removes 100% of
      "Lorem ipsum / Accenture" placeholder text AND removes the floating body positioned
      object `z.000000000.i.4` (topOffset=385.5pt) that would otherwise overlap body text.
    * Inserts a clean pageBreak after Page 1 Cover so Page 2 starts cleanly.
    * Uses official Cloudstyle typography (Google Sans + Roboto) and Cloudstyle table
      formatting (#4285f4 header row, #f1f3f4 alternating rows, 10.8pt padding).
  - In Google Slides:
    * Clones 1Afld8EjwWm2H9hTxE82vg_kAzoFANMYNkjNsQrdQdKg, retains 12 clean layout slides
      ([0, 1, 4, 2, 45, 43, 40, 35, 36, 42, 78, 83]), and deletes all other 72 slides.
    * Replaces text in every shape/table cell using strictly bounded text lengths and line
      counts matching the original template boxes so zero text overflow or overlap occurs.
"""

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

SSL_CTX = ssl._create_unverified_context()
QUOTA_PROJECT = "jsaccomani-pqc-agent-2610"
PQC_FOLDER_ID = "1VN0-Lt766Tm36JRNj74LnsAy8h8MwBb0"

OFFICIAL_DOC_TEMPLATE_ID = "1x9L5sz5V0CpbEoo_4jl5wQm7l9PlyHADrzXpnODWtbQ"
OFFICIAL_SLIDES_TEMPLATE_ID = "1Afld8EjwWm2H9hTxE82vg_kAzoFANMYNkjNsQrdQdKg"

# Official Cloudstyle RGB Palette from 1x9L5sz5V0CpbEoo_4jl5wQm7l9PlyHADrzXpnODWtbQ
RGB_CLOUD_BLUE = {"red": 0.25882354, "green": 0.52156866, "blue": 0.95686275}   # #4285f4
RGB_DARK_INK = {"red": 0.1254902, "green": 0.12941177, "blue": 0.14117648}      # #202124
RGB_BODY_GRAY = {"red": 0.2627451, "green": 0.2627451, "blue": 0.2627451}       # #434343
RGB_MUTED_GRAY = {"red": 0.45, "green": 0.47, "blue": 0.49}                     # Cover subtitle
RGB_CARD_GRAY = {"red": 0.94509804, "green": 0.9529412, "blue": 0.95686275}     # #f1f3f4
RGB_BORDER_GRAY = {"red": 0.8, "green": 0.8, "blue": 0.8}                       # #cccccc
RGB_WHITE = {"red": 1.0, "green": 1.0, "blue": 1.0}


def get_token():
    adc_path = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
    with open(adc_path, "r", encoding="utf-8") as f:
        adc = json.load(f)
    data = urllib.parse.urlencode({
        "client_id": adc["client_id"],
        "client_secret": adc["client_secret"],
        "refresh_token": adc["refresh_token"],
        "grant_type": "refresh_token",
    }).encode("utf-8")
    req = urllib.request.Request("https://oauth2.googleapis.com/token", data=data, method="POST")
    with urllib.request.urlopen(req, timeout=15, context=SSL_CTX) as resp:
        return json.loads(resp.read().decode("utf-8"))["access_token"]


def api_json(method, url, token, body=None):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-goog-user-project": QUOTA_PROJECT,
    }
    data = json.dumps(body).encode("utf-8") if body is not None else None
    for attempt in range(4):
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60, context=SSL_CTX) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            if e.code in (403, 429, 500, 503) and attempt < 3:
                time.sleep(2.5 * (attempt + 1))
                continue
            raise RuntimeError(f"HTTP {e.code} on {method} {url}: {err[:500]}")


def utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


def clone_file_and_replace_old(token, template_id, folder_id, target_name, old_names=None):
    q = urllib.parse.quote(f"'{folder_id}' in parents and trashed = false")
    url_q = f"https://www.googleapis.com/drive/v3/files?q={q}&fields=files(id,name,mimeType)&supportsAllDrives=true&includeItemsFromAllDrives=true"
    existing = api_json("GET", url_q, token).get("files", [])

    copy_url = f"https://www.googleapis.com/drive/v3/files/{template_id}/copy?fields=id,name,webViewLink&supportsAllDrives=true"
    new_file = api_json(
        "POST",
        copy_url,
        token,
        body={"name": target_name, "parents": [folder_id]},
    )
    new_id = new_file["id"]

    names_to_trash = set([target_name] + list(old_names or []))
    for f in existing:
        fid = f["id"]
        if fid == new_id:
            continue
        if f["name"] in names_to_trash:
            try:
                api_json(
                    "PATCH",
                    f"https://www.googleapis.com/drive/v3/files/{fid}?supportsAllDrives=true",
                    token,
                    body={"trashed": True},
                )
            except Exception:
                pass
    return new_file


def normalize_doc_text(s: str) -> str:
    if not isinstance(s, str):
        return str(s)
    replacements = [
        ("01_SOW_PQC_Readiness_Assessment_Template.md", "Agentic PQC SOW Readiness Assessment Template"),
        ("01_SOW_PQC_Readiness_Assessment_Template", "Agentic PQC SOW Readiness Assessment Template"),
        ("SOW_PQC_Readiness_Assessment_Template", "Agentic PQC SOW Readiness Assessment Template"),
        ("02_PQC_Technical_Design_Document_TDD.md", "Agentic PQC Technical Design Document TDD"),
        ("02_PQC_Technical_Design_Document_TDD", "Agentic PQC Technical Design Document TDD"),
        ("PQC_Technical_Design_Document_TDD", "Agentic PQC Technical Design Document TDD"),
        ("03_PQC_CISO_Recommendations_Book.md", "Agentic PQC Security Recommendations Book"),
        ("03_PQC_CISO_Recommendations_Book", "Agentic PQC Security Recommendations Book"),
        ("PQC_CISO_Recommendations_Book", "Agentic PQC Security Recommendations Book"),
        ("CISO Strategic Recommendations Book", "Agentic PQC Security Recommendations Book"),
        ("Executive CISO Recommendations Book", "Agentic PQC Security Recommendations Book"),
        ("CISO Recommendations Book", "Agentic PQC Security Recommendations Book"),
        ("04_PQC_Kickoff_Engagement_Deck.md", "Agentic PQC Kickoff Engagement Deck"),
        ("04_PQC_Kickoff_Engagement_Deck", "Agentic PQC Kickoff Engagement Deck"),
        ("PQC_Kickoff_Engagement_Deck", "Agentic PQC Kickoff Engagement Deck"),
        ("05_PQC_Delivery_Model_and_Sizing_Guide.md", "Agentic PQC Delivery Model and Sizing Guide"),
        ("05_PQC_Delivery_Model_and_Sizing_Guide", "Agentic PQC Delivery Model and Sizing Guide"),
        ("PQC_Delivery_Model_and_Sizing_Guide", "Agentic PQC Delivery Model and Sizing Guide"),
        ("06_PQC_Elevator_Pitch_and_Lab_Prompts.md", "Agentic PQC Elevator Pitch and Lab Prompts"),
        ("06_PQC_Elevator_Pitch_and_Lab_Prompts", "Agentic PQC Elevator Pitch and Lab Prompts"),
        ("PQC_Elevator_Pitch_and_Lab_Prompts", "Agentic PQC Elevator Pitch and Lab Prompts"),
        ("07_PQC_Discovery_Questionnaire.md", "Agentic PQC Discovery Questionnaire"),
        ("07_PQC_Discovery_Questionnaire", "Agentic PQC Discovery Questionnaire"),
        ("PQC_Discovery_Questionnaire", "Agentic PQC Discovery Questionnaire"),
        ("08_PQC_System_Architecture_Specification.md", "Agentic PQC System Architecture Specification"),
        ("08_PQC_System_Architecture_Specification", "Agentic PQC System Architecture Specification"),
        ("PQC_System_Architecture_Specification", "Agentic PQC System Architecture Specification"),
        ("09_PQC_User_and_Consultant_Guide.md", "Agentic PQC User and Consultant Guide"),
        ("09_PQC_User_and_Consultant_Guide", "Agentic PQC User and Consultant Guide"),
        ("PQC_User_and_Consultant_Guide", "Agentic PQC User and Consultant Guide"),
        ("10_PQC_Executive_Presentation_Deck_GCC_Ideation", "Agentic PQC Executive Presentation Deck GCC Ideation"),
        ("PQC_Executive_Presentation_Deck_GCC_Ideation", "Agentic PQC Executive Presentation Deck GCC Ideation"),
        ("11_PQC_Sample_Live_Assessment_Report_31564119954.md", "Agentic PQC Sample Live Assessment Report 31564119954"),
        ("11_PQC_Sample_Live_Assessment_Report_31564119954", "Agentic PQC Sample Live Assessment Report 31564119954"),
        ("PQC_Sample_Live_Assessment_Report_31564119954", "Agentic PQC Sample Live Assessment Report 31564119954"),
        ("PQC_Sample_Live_Assessment_Report", "Agentic PQC Sample Live Assessment Report"),
        ("README.md", "Agentic PQC README"),
        ("master README", "Agentic PQC README"),
        ("____________________________________", "[ Authorized Electronic or Physical Signature ]"),
        ("pqc_inventory_agent", "pqc-inventory-agent"),
    ]
    out = s
    for old, new in replacements:
        out = out.replace(old, new)
    # Remove any remaining underscores ("underlines")
    out = out.replace("_", "-")
    return out


def populate_cloudstyle_doc(token, doc_id, cover_title_2lines, cover_subtitle, page2_headline, page2_subtitle, exec_summary_text, blocks):
    """
    Populates a cloned copy of `Cloudstyle Google Docs Template` (1x9L5sz5V0CpbEoo_4jl5wQm7l9PlyHADrzXpnODWtbQ).
    Ensures every document includes 'Agentic PQC', replaces CISO Recommendations Book with
    Agentic PQC Security Recommendations Book, and removes all underscores/underlines.
    """
    cover_title_2lines = normalize_doc_text(cover_title_2lines).replace("Post-Quantum Cryptography\u000b", "Agentic PQC Readiness\u000b")
    if "Agentic PQC" not in cover_title_2lines:
        cover_title_2lines = "Agentic PQC\u000b" + cover_title_2lines
    cover_subtitle = normalize_doc_text(cover_subtitle)
    page2_headline = normalize_doc_text(page2_headline)
    if "Agentic PQC" not in page2_headline:
        if "PQC" in page2_headline:
            page2_headline = page2_headline.replace("PQC", "Agentic PQC", 1)
        else:
            page2_headline = "Agentic PQC: " + page2_headline
    page2_subtitle = normalize_doc_text(page2_subtitle)
    exec_summary_text = normalize_doc_text(exec_summary_text)
    if "Agentic PQC" not in exec_summary_text:
        exec_summary_text = exec_summary_text.replace("Post-Quantum Cryptography (PQC)", "Agentic Post-Quantum Cryptography (Agentic PQC)", 1)

    norm_blocks = []
    for b_type, b_data in blocks:
        if isinstance(b_data, str):
            norm_blocks.append((b_type, normalize_doc_text(b_data)))
        elif b_type in ("BULLETS", "NUMBERED"):
            norm_blocks.append((b_type, [normalize_doc_text(item) for item in b_data]))
        elif b_type == "TABLE":
            norm_blocks.append((b_type, [[normalize_doc_text(cell) for cell in row] for row in b_data]))
        else:
            norm_blocks.append((b_type, b_data))
    blocks = norm_blocks

    doc = api_json("GET", f"https://docs.googleapis.com/v1/documents/{doc_id}", token)
    content = doc["body"]["content"]
    doc_end = content[-1]["endIndex"] - 1

    # Check if Page 1 already has a pageBreak and no broken inline image i.0
    pb_end_idx = None
    for el in content[:12]:
        if "paragraph" in el:
            for pe in el["paragraph"].get("elements", []):
                if "pageBreak" in pe:
                    pb_end_idx = el["endIndex"]
                    break
        if pb_end_idx is not None:
            break

    if (pb_end_idx is not None and "i.0" not in doc.get("inlineObjects", {})) or (len(content) > 3 and content[3].get("endIndex", 0) - content[3].get("startIndex", 0) <= 1):
        pass1_clean_reqs = []
        if doc_end > 1:
            pass1_clean_reqs.append(
                {"deleteContentRange": {"range": {"startIndex": 1, "endIndex": doc_end}}}
            )
        title_block = "\n\n\n\n" + cover_title_2lines + "\n"
        spacer_block = "\n"
        sub_block = cover_subtitle
        full_p1 = title_block + spacer_block + sub_block
        t_len = utf16_len(title_block)
        sp_len = utf16_len(spacer_block)
        sub_len = utf16_len(sub_block)
        pass1_clean_reqs.extend([
            {"insertText": {"location": {"index": 1}, "text": full_p1}},
            {
                "updateParagraphStyle": {
                    "range": {"startIndex": 1, "endIndex": 1 + t_len},
                    "paragraphStyle": {
                        "namedStyleType": "NORMAL_TEXT",
                        "lineSpacing": 115.0,
                        "spaceAbove": {"magnitude": 0, "unit": "PT"},
                        "spaceBelow": {"magnitude": 4, "unit": "PT"},
                    },
                    "fields": "namedStyleType,lineSpacing,spaceAbove,spaceBelow",
                }
            },
            {
                "updateTextStyle": {
                    "range": {"startIndex": 1, "endIndex": 1 + t_len - 1},
                    "textStyle": {
                        "bold": False,
                        "foregroundColor": {"color": {"rgbColor": RGB_DARK_INK}},
                        "fontSize": {"magnitude": 34, "unit": "PT"},
                        "weightedFontFamily": {"fontFamily": "Google Sans", "weight": 500},
                    },
                    "fields": "bold,foregroundColor,fontSize,weightedFontFamily",
                }
            },
            {
                "updateParagraphStyle": {
                    "range": {"startIndex": 1 + t_len, "endIndex": 1 + t_len + sp_len + sub_len},
                    "paragraphStyle": {
                        "namedStyleType": "NORMAL_TEXT",
                        "lineSpacing": 100.0,
                        "spaceAbove": {"magnitude": 0, "unit": "PT"},
                        "spaceBelow": {"magnitude": 0, "unit": "PT"},
                    },
                    "fields": "namedStyleType,lineSpacing,spaceAbove,spaceBelow",
                }
            },
            {
                "updateTextStyle": {
                    "range": {"startIndex": 1 + t_len, "endIndex": 1 + t_len + sp_len},
                    "textStyle": {
                        "bold": False,
                        "fontSize": {"magnitude": 15, "unit": "PT"},
                        "weightedFontFamily": {"fontFamily": "Google Sans", "weight": 400},
                    },
                    "fields": "bold,fontSize,weightedFontFamily",
                }
            },
            {
                "updateTextStyle": {
                    "range": {"startIndex": 1 + t_len + sp_len, "endIndex": 1 + t_len + sp_len + sub_len},
                    "textStyle": {
                        "bold": False,
                        "foregroundColor": {"color": {"rgbColor": RGB_MUTED_GRAY}},
                        "fontSize": {"magnitude": 13, "unit": "PT"},
                        "weightedFontFamily": {"fontFamily": "Google Sans", "weight": 400},
                    },
                    "fields": "bold,foregroundColor,fontSize,weightedFontFamily",
                }
            },
            {
                "insertPageBreak": {
                    "location": {"index": 1 + t_len + sp_len + sub_len}
                }
            },
        ])
        api_json(
            "POST",
            f"https://docs.googleapis.com/v1/documents/{doc_id}:batchUpdate",
            token,
            body={"requests": pass1_clean_reqs},
        )
    else:
        el1 = content[1]
        el3 = content[3]
        pass1_reqs = []
        if "z.000000000.i.4" in doc.get("positionedObjects", {}):
            pass1_reqs.append({"deletePositionedObject": {"objectId": "z.000000000.i.4"}})
        pass1_reqs.extend([
            {
                "deleteContentRange": {
                    "range": {"startIndex": el3["endIndex"] - 1, "endIndex": doc_end}
                }
            },
            {
                "deleteContentRange": {
                    "range": {"startIndex": el3["startIndex"], "endIndex": el3["endIndex"] - 1}
                }
            },
            {
                "insertText": {
                    "location": {"index": el3["startIndex"]},
                    "text": cover_subtitle,
                }
            },
            {
                "updateTextStyle": {
                    "range": {
                        "startIndex": el3["startIndex"],
                        "endIndex": el3["startIndex"] + utf16_len(cover_subtitle),
                    },
                    "textStyle": {
                        "bold": False,
                        "foregroundColor": {"color": {"rgbColor": RGB_MUTED_GRAY}},
                        "fontSize": {"magnitude": 13, "unit": "PT"},
                        "weightedFontFamily": {"fontFamily": "Google Sans", "weight": 400},
                    },
                    "fields": "bold,foregroundColor,fontSize,weightedFontFamily",
                }
            },
            {
                "deleteContentRange": {
                    "range": {"startIndex": el1["startIndex"], "endIndex": el1["endIndex"] - 1}
                }
            },
            {
                "insertText": {
                    "location": {"index": el1["startIndex"]},
                    "text": "\n\n\n\n" + cover_title_2lines,
                }
            },
            {
                "updateParagraphStyle": {
                    "range": {
                        "startIndex": 1,
                        "endIndex": 1 + 4 + utf16_len(cover_title_2lines) + 1,
                    },
                    "paragraphStyle": {
                        "lineSpacing": 115.0,
                        "spaceBelow": {"magnitude": 4, "unit": "PT"},
                    },
                    "fields": "lineSpacing,spaceBelow",
                }
            },
            {
                "updateTextStyle": {
                    "range": {
                        "startIndex": 1,
                        "endIndex": 1 + 4 + utf16_len(cover_title_2lines),
                    },
                    "textStyle": {
                        "bold": False,
                        "foregroundColor": {"color": {"rgbColor": RGB_DARK_INK}},
                        "fontSize": {"magnitude": 34, "unit": "PT"},
                        "weightedFontFamily": {"fontFamily": "Google Sans", "weight": 500},
                    },
                    "fields": "bold,foregroundColor,fontSize,weightedFontFamily",
                }
            },
        ])
        api_json(
            "POST",
            f"https://docs.googleapis.com/v1/documents/{doc_id}:batchUpdate",
            token,
            body={"requests": pass1_reqs},
        )
        doc = api_json("GET", f"https://docs.googleapis.com/v1/documents/{doc_id}", token)
        pb_index = doc["body"]["content"][-1]["endIndex"] - 1
        api_json(
            "POST",
            f"https://docs.googleapis.com/v1/documents/{doc_id}:batchUpdate",
            token,
            body={"requests": [{"insertPageBreak": {"location": {"index": pb_index}}}]},
        )

    # Read back doc to get exact starting cursor on Page 2
    doc = api_json("GET", f"https://docs.googleapis.com/v1/documents/{doc_id}", token)
    cursor = doc["body"]["content"][-1]["endIndex"] - 1

    # PASS 2: Insert Page 2 Headline, Subtitle, Metadata, Executive Summary, and all body blocks
    pass2_reqs = []
    tables_to_insert = []

    def add_para(text_str, named_style, font_family, font_weight, font_size, rgb_color, space_above=0.0, space_below=6.0, line_spacing=135.0, bold_prefix_len=0, bg_color=None):
        nonlocal cursor
        txt = text_str.strip() + "\n"
        start = cursor
        end = start + utf16_len(txt)
        pass2_reqs.append({"insertText": {"location": {"index": start}, "text": txt}})
        p_style = {
            "namedStyleType": named_style,
            "lineSpacing": line_spacing,
            "spaceAbove": {"magnitude": space_above, "unit": "PT"},
            "spaceBelow": {"magnitude": space_below, "unit": "PT"},
            "keepLinesTogether": named_style != "NORMAL_TEXT",
            "keepWithNext": named_style != "NORMAL_TEXT",
        }
        p_fields = "namedStyleType,lineSpacing,spaceAbove,spaceBelow,keepLinesTogether,keepWithNext"
        if bg_color:
            p_style["shading"] = {"backgroundColor": {"color": {"rgbColor": bg_color}}}
            p_fields += ",shading"
        pass2_reqs.append({
            "updateParagraphStyle": {
                "range": {"startIndex": start, "endIndex": end},
                "paragraphStyle": p_style,
                "fields": p_fields,
            }
        })
        pass2_reqs.append({
            "updateTextStyle": {
                "range": {"startIndex": start, "endIndex": end - 1},
                "textStyle": {
                    "bold": font_weight >= 600,
                    "foregroundColor": {"color": {"rgbColor": rgb_color}},
                    "fontSize": {"magnitude": font_size, "unit": "PT"},
                    "weightedFontFamily": {"fontFamily": font_family, "weight": font_weight},
                },
                "fields": "bold,foregroundColor,fontSize,weightedFontFamily",
            }
        })
        if bold_prefix_len > 0:
            pass2_reqs.append({
                "updateTextStyle": {
                    "range": {"startIndex": start, "endIndex": start + bold_prefix_len},
                    "textStyle": {
                        "bold": True,
                        "foregroundColor": {"color": {"rgbColor": RGB_DARK_INK}},
                    },
                    "fields": "bold,foregroundColor",
                }
            })
        cursor = end

    # Page 2 Cloudstyle Title & Subtitle
    add_para(page2_headline, "TITLE", "Google Sans", 500, 22, RGB_DARK_INK, space_above=0.0, space_below=4.0, line_spacing=115.0)
    add_para(page2_subtitle, "SUBTITLE", "Google Sans", 400, 12, RGB_CLOUD_BLUE, space_above=0.0, space_below=10.0, line_spacing=125.0)

    # Metadata block
    meta_lines = [
        ("Organization:", " Google Cloud Consulting (GCC Latam / PSO AI Infra & Security)"),
        ("Author:", " Joabson Saccomani (jsaccomani@google.com)"),
        ("Runtime Stack:", " Google ADK, Gemini 3.1 Pro / 2.5 Pro, Vertex AI Agent Engine, Google Cloud Run"),
        ("Standards Alignment:", " NIST FIPS 203/204/205, NIST IR 8547 (Final, Oct 2026), EO 14412, OMB M-26-15, UK NCSC (2028/2031/2035), CNSA 2.0, CycloneDX v1.6"),
    ]
    for m_lead, m_rest in meta_lines:
        add_para(
            f"{m_lead}{m_rest}",
            "NORMAL_TEXT",
            "Roboto",
            400,
            10,
            RGB_BODY_GRAY,
            space_above=0.0,
            space_below=2.0,
            line_spacing=120.0,
            bold_prefix_len=utf16_len(m_lead),
        )

    # Executive Summary Callout Card (1x1 Cloudstyle table)
    t_exec_idx = len(tables_to_insert)
    marker_exec = f"[[TABLE_{t_exec_idx}]]\n"
    m_start = cursor
    m_end = m_start + utf16_len(marker_exec)
    pass2_reqs.append({"insertText": {"location": {"index": m_start}, "text": marker_exec}})
    tables_to_insert.append(("CALLOUT", [[f"Executive Summary: {exec_summary_text}"]]))
    cursor = m_end

    # Document Body Blocks
    for b_type, b_data in blocks:
        if b_type == "H2":
            add_para(b_data, "HEADING_1", "Google Sans", 500, 16, RGB_DARK_INK, space_above=14.0, space_below=6.0, line_spacing=115.0)
        elif b_type == "H3":
            add_para(b_data, "HEADING_2", "Google Sans", 500, 12.5, RGB_CLOUD_BLUE, space_above=10.0, space_below=4.0, line_spacing=115.0)
        elif b_type == "P":
            pref_len = utf16_len(b_data.split(":", 1)[0] + ":") if ":" in b_data and len(b_data.split(":", 1)[0]) < 55 else 0
            add_para(b_data, "NORMAL_TEXT", "Roboto", 400, 10.5, RGB_BODY_GRAY, space_above=0.0, space_below=6.0, line_spacing=135.0, bold_prefix_len=pref_len)
        elif b_type in ("BULLETS", "NUMBERED"):
            list_start = cursor
            for item in b_data:
                line_str = item.strip()
                pref_len = utf16_len(line_str.split(":", 1)[0] + ":") if ":" in line_str and len(line_str.split(":", 1)[0]) < 65 else 0
                add_para(line_str, "NORMAL_TEXT", "Roboto", 400, 10.5, RGB_BODY_GRAY, space_above=0.0, space_below=4.0, line_spacing=130.0, bold_prefix_len=pref_len)
            list_end = cursor
            preset = "BULLET_DISC_CIRCLE_SQUARE" if b_type == "BULLETS" else "NUMBERED_DECIMAL_ALPHA_ROMAN"
            pass2_reqs.append({
                "createParagraphBullets": {
                    "range": {"startIndex": list_start, "endIndex": list_end},
                    "bulletPreset": preset,
                }
            })
        elif b_type == "TABLE":
            t_idx = len(tables_to_insert)
            marker = f"[[TABLE_{t_idx}]]\n"
            start = cursor
            end = start + utf16_len(marker)
            pass2_reqs.append({"insertText": {"location": {"index": start}, "text": marker}})
            tables_to_insert.append(("DATA", b_data))
            cursor = end

    api_json(
        "POST",
        f"https://docs.googleapis.com/v1/documents/{doc_id}:batchUpdate",
        token,
        body={"requests": pass2_reqs},
    )

    # PASS 3: Replace [[TABLE_i]] markers with native tables in reverse order
    doc = api_json("GET", f"https://docs.googleapis.com/v1/documents/{doc_id}", token)
    marker_positions = []
    for el in doc["body"]["content"]:
        if "paragraph" in el:
            txt = "".join(e.get("textRun", {}).get("content", "") for e in el["paragraph"].get("elements", []))
            for t_idx in range(len(tables_to_insert)):
                if f"[[TABLE_{t_idx}]]" in txt:
                    marker_positions.append((t_idx, el["startIndex"], el["endIndex"]))

    pass3_reqs = []
    for t_idx, m_start, m_end in sorted(marker_positions, key=lambda x: x[1], reverse=True):
        _, rows_data = tables_to_insert[t_idx]
        num_rows = len(rows_data)
        num_cols = len(rows_data[0])
        pass3_reqs.append({
            "deleteContentRange": {
                "range": {"startIndex": m_start, "endIndex": m_end}
            }
        })
        pass3_reqs.append({
            "insertTable": {
                "rows": num_rows,
                "columns": num_cols,
                "location": {"index": m_start},
            }
        })

    api_json(
        "POST",
        f"https://docs.googleapis.com/v1/documents/{doc_id}:batchUpdate",
        token,
        body={"requests": pass3_reqs},
    )

    # PASS 4: Populate and style all tables in reverse order using official Cloudstyle Table [38] / [14] styling
    doc = api_json("GET", f"https://docs.googleapis.com/v1/documents/{doc_id}", token)
    table_elements = [el for el in doc["body"]["content"] if "table" in el]

    pass4_reqs = []
    for el in doc["body"]["content"][8:]:
        if "paragraph" in el and el.get("endIndex", 0) - el.get("startIndex", 0) == 1:
            p_st = el["paragraph"].get("paragraphStyle", {}).get("namedStyleType", "")
            if p_st.startswith("HEADING") or p_st in ("TITLE", "SUBTITLE"):
                pass4_reqs.append({
                    "updateParagraphStyle": {
                        "range": {"startIndex": el["startIndex"], "endIndex": el["endIndex"]},
                        "paragraphStyle": {
                            "namedStyleType": "NORMAL_TEXT",
                            "lineSpacing": 100.0,
                            "spaceAbove": {"magnitude": 0.0, "unit": "PT"},
                            "spaceBelow": {"magnitude": 2.0, "unit": "PT"},
                        },
                        "fields": "namedStyleType,lineSpacing,spaceAbove,spaceBelow",
                    }
                })
    border_std = {
        "color": {"color": {"rgbColor": RGB_BORDER_GRAY}},
        "width": {"magnitude": 1, "unit": "PT"},
        "dashStyle": "SOLID",
    }
    border_callout_left = {
        "color": {"color": {"rgbColor": RGB_CLOUD_BLUE}},
        "width": {"magnitude": 3, "unit": "PT"},
        "dashStyle": "SOLID",
    }
    border_none = {
        "color": {"color": {"rgbColor": RGB_CARD_GRAY}},
        "width": {"magnitude": 0, "unit": "PT"},
        "dashStyle": "SOLID",
    }

    for t_idx in range(len(table_elements) - 1, -1, -1):
        if t_idx >= len(tables_to_insert):
            continue
        t_el = table_elements[t_idx]
        t_start = t_el["startIndex"]
        t_kind, rows_data = tables_to_insert[t_idx]
        num_rows = len(rows_data)
        num_cols = len(rows_data[0])

        if t_kind == "CALLOUT":
            cell_text = rows_data[0][0]
            cell_el = t_el["table"]["tableRows"][0]["tableCells"][0]
            cell_p_start = cell_el["content"][0]["startIndex"]
            cell_p_end = cell_p_start + utf16_len(cell_text)
            pass4_reqs.append({
                "updateTableCellStyle": {
                    "tableRange": {
                        "tableCellLocation": {
                            "tableStartLocation": {"index": t_start},
                            "rowIndex": 0,
                            "columnIndex": 0,
                        },
                        "rowSpan": 1,
                        "columnSpan": 1,
                    },
                    "tableCellStyle": {
                        "backgroundColor": {"color": {"rgbColor": RGB_CARD_GRAY}},
                        "borderLeft": border_callout_left,
                        "borderRight": border_none,
                        "borderTop": border_none,
                        "borderBottom": border_none,
                        "paddingLeft": {"magnitude": 10.8, "unit": "PT"},
                        "paddingRight": {"magnitude": 10.8, "unit": "PT"},
                        "paddingTop": {"magnitude": 10.8, "unit": "PT"},
                        "paddingBottom": {"magnitude": 10.8, "unit": "PT"},
                    },
                    "fields": "backgroundColor,borderLeft,borderRight,borderTop,borderBottom,paddingLeft,paddingRight,paddingTop,paddingBottom",
                }
            })
            pass4_reqs.append({
                "insertText": {"location": {"index": cell_p_start}, "text": cell_text}
            })
            pass4_reqs.append({
                "updateTextStyle": {
                    "range": {"startIndex": cell_p_start, "endIndex": cell_p_end},
                    "textStyle": {
                        "bold": False,
                        "foregroundColor": {"color": {"rgbColor": RGB_DARK_INK}},
                        "fontSize": {"magnitude": 10.5, "unit": "PT"},
                        "weightedFontFamily": {"fontFamily": "Roboto", "weight": 400},
                    },
                    "fields": "bold,foregroundColor,fontSize,weightedFontFamily",
                }
            })
            pass4_reqs.append({
                "updateTextStyle": {
                    "range": {
                        "startIndex": cell_p_start,
                        "endIndex": cell_p_start + utf16_len("Executive Summary:"),
                    },
                    "textStyle": {
                        "bold": True,
                        "foregroundColor": {"color": {"rgbColor": RGB_CLOUD_BLUE}},
                    },
                    "fields": "bold,foregroundColor",
                }
            })
            continue

        # Standard Cloudstyle Data Table (matches Table [38] of Cloudstyle Google Docs Template)
        for r_idx in range(num_rows - 1, -1, -1):
            is_header = (r_idx == 0)
            bg_color = RGB_CLOUD_BLUE if is_header else (RGB_CARD_GRAY if r_idx % 2 == 1 else RGB_WHITE)
            pass4_reqs.append({
                "updateTableCellStyle": {
                    "tableRange": {
                        "tableCellLocation": {
                            "tableStartLocation": {"index": t_start},
                            "rowIndex": r_idx,
                            "columnIndex": 0,
                        },
                        "rowSpan": 1,
                        "columnSpan": num_cols,
                    },
                    "tableCellStyle": {
                        "backgroundColor": {"color": {"rgbColor": bg_color}},
                        "borderLeft": border_std,
                        "borderRight": border_std,
                        "borderTop": border_std,
                        "borderBottom": border_std,
                        "paddingLeft": {"magnitude": 9.0, "unit": "PT"},
                        "paddingRight": {"magnitude": 9.0, "unit": "PT"},
                        "paddingTop": {"magnitude": 8.0, "unit": "PT"},
                        "paddingBottom": {"magnitude": 8.0, "unit": "PT"},
                        "contentAlignment": "TOP",
                    },
                    "fields": "backgroundColor,borderLeft,borderRight,borderTop,borderBottom,paddingLeft,paddingRight,paddingTop,paddingBottom,contentAlignment",
                }
            })

            for c_idx in range(num_cols - 1, -1, -1):
                cell_text = str(rows_data[r_idx][c_idx]).strip()
                if not cell_text:
                    continue
                cell_el = t_el["table"]["tableRows"][r_idx]["tableCells"][c_idx]
                cell_p_start = cell_el["content"][0]["startIndex"]
                cell_p_end = cell_p_start + utf16_len(cell_text)
                pass4_reqs.append({
                    "insertText": {
                        "location": {"index": cell_p_start},
                        "text": cell_text,
                    }
                })
                pass4_reqs.append({
                    "updateTextStyle": {
                        "range": {"startIndex": cell_p_start, "endIndex": cell_p_end},
                        "textStyle": {
                            "bold": True if (is_header or c_idx == 0) else False,
                            "foregroundColor": {
                                "color": {"rgbColor": RGB_WHITE if is_header else RGB_DARK_INK}
                            },
                            "fontSize": {"magnitude": 9.5, "unit": "PT"},
                            "weightedFontFamily": {
                                "fontFamily": "Google Sans" if is_header else "Roboto",
                                "weight": 500 if (is_header or c_idx == 0) else 400,
                            },
                        },
                        "fields": "bold,foregroundColor,fontSize,weightedFontFamily",
                    }
                })

    pass4_reqs.append({
        "replaceAllText": {
            "containsText": {"text": "For more information visit cloud.google.com", "matchCase": False},
            "replaceText": "",
        }
    })
    if pass4_reqs:
        api_json(
            "POST",
            f"https://docs.googleapis.com/v1/documents/{doc_id}:batchUpdate",
            token,
            body={"requests": pass4_reqs},
        )



def build_official_slides_presentation(token, folder_id, target_name, old_names=None):
    """
    Clones the official Google Cloud 2026 Playbook Slides template
    (1Afld8EjwWm2H9hTxE82vg_kAzoFANMYNkjNsQrdQdKg), retains the 12 cleanest layout
    slides ([0, 1, 4, 2, 45, 43, 40, 35, 36, 42, 78, 83]), deletes all other 72 slides,
    and replaces every text box and table cell with strictly length-bounded PQC content
    to guarantee zero text overlapping and zero template residue.
    """
    cloned = clone_file_and_replace_old(
        token,
        OFFICIAL_SLIDES_TEMPLATE_ID,
        folder_id,
        target_name,
        old_names=old_names,
    )
    pres_id = cloned["id"]
    pres = api_json("GET", f"https://slides.googleapis.com/v1/presentations/{pres_id}", token)
    all_slides = pres.get("slides", [])

    keep_indices = [0, 1, 4, 2, 45, 43, 40, 35, 36, 42, 78, 83]
    keep_slide_ids = [all_slides[i]["objectId"] for i in keep_indices]
    keep_set = set(keep_slide_ids)

    reqs = []
    # 1. Delete all 72 unused slides so zero "mídia generativa / Veo / Nano-Banana" slides remain
    for sl in all_slides:
        sid = sl["objectId"]
        if sid not in keep_set:
            reqs.append({"deleteObject": {"objectId": sid}})

    # 2. Reorder kept slides into logical presentation sequence
    for pos_idx, sid in enumerate(keep_slide_ids):
        reqs.append({
            "updateSlidesPosition": {
                "slideObjectIds": [sid],
                "insertionIndex": pos_idx,
            }
        })

    # Helper to replace text inside a shape without altering its original font size/color
    def set_shape_text(shape_id, new_text):
        reqs.append({
            "deleteText": {
                "objectId": shape_id,
                "textRange": {"type": "ALL"},
            }
        })
        reqs.append({
            "insertText": {
                "objectId": shape_id,
                "insertionIndex": 0,
                "text": new_text,
            }
        })

    def set_table_cell_text(table_id, row_idx, col_idx, new_text, had_text=True):
        if had_text:
            reqs.append({
                "deleteText": {
                    "objectId": table_id,
                    "cellLocation": {"rowIndex": row_idx, "columnIndex": col_idx},
                    "textRange": {"type": "ALL"},
                }
            })
        reqs.append({
            "insertText": {
                "objectId": table_id,
                "cellLocation": {"rowIndex": row_idx, "columnIndex": col_idx},
                "insertionIndex": 0,
                "text": new_text,
            }
        })

    # --- Slide [0] (g3868b008361_1_454): Cover Slide ---
    reqs.append({"deleteObject": {"objectId": "g3868b008361_1_459"}})
    reqs.append({"deleteObject": {"objectId": "g3868b008361_2_1015"}})
    set_shape_text("g3868b008361_1_458", "Agentic PQC Readiness & CBOM Engine")
    set_shape_text("g3868b008361_1_457", "Google Cloud Consulting (PSO) — Post-Quantum Cryptography")

    # --- Slide [1] (g3868b008361_2_1001): Executive Objective, Audience & Scope (orig len=739) ---
    set_shape_text(
        "g3868b008361_2_1004",
        (
            "Objective\n\n"
            "Automate cryptographic discovery, quantum physics risk modeling (Q-VaR), and migration "
            "to Post-Quantum Cryptography (NIST FIPS 203/204/205, NIST IR 8547 & EO 14412) on Google Cloud in 7 seconds.\n"
            "Target Audience\n"
            "CISOs, Chief Risk Officers, Google Cloud Security Architects (PSO, TAM, CE), and Platform Engineering teams.\n"
            "Technical Scope\n"
            "100% read-only inspection across Cloud KMS/HSM, Cloud Asset Inventory, TLS 1.3 (X25519MLKEM768), and BYOK."
        ),
    )

    # --- Slide [4] (g3868b008361_2_1031): Executive Agenda (8 lines matching 01..08) ---
    set_shape_text(
        "g3868b008361_2_1038",
        "01\n02\n03\n04\n05\n06\n07\n08",
    )
    set_shape_text(
        "g3868b008361_2_1039",
        (
            "HNDL Threat & Mosca's Theorem (X + Y > Z)\n"
            "Agentic Solution Overview (ADK & Gemini 3.1)\n"
            "4-Layer Cryptographic Discovery (7 Seconds)\n"
            "Quantum Physics Engine (Shor, Roetteler & Grover)\n"
            "Executive Scorecard & Financial Q-VaR Modeling\n"
            "Consultative 5-Step Runbooks (Cloud HSM)\n"
            "3-Phase Delivery Roadmap (PSO & TAM)\n"
            "Commercial Pull-Through & Multi-Persona Outputs"
        ),
    )

    # --- Slide [2] (g3868b008361_2_1013): Solution Overview (Target, Problem, Offer, Value) ---
    set_shape_text("g3868b008361_2_1014", "PQC Solution Overview")
    set_shape_text("g3868b008361_2_1024", "Target Customer")
    set_shape_text(
        "g3868b008361_2_1018",
        "Financial services, healthcare, public sector, telecom, and enterprises with long-shelf-life data (>5 years).",
    )
    set_shape_text("g3868b008361_2_1025", "Problem Statement")
    set_shape_text(
        "g3868b008361_2_1022",
        (
            "Adversaries actively intercept encrypted traffic today via Harvest Now, Decrypt Later (HNDL) attacks "
            "for future decryption using Shor's Algorithm. NIST IR 8547 (Final), EO 14412, and CNSA 2.0 mandate "
            "deprecating RSA and ECDSA by 2030, yet manual audits take weeks."
        ),
    )
    set_shape_text("g3868b008361_2_1026", "Agentic Offering")
    set_shape_text(
        "g3868b008361_2_1023",
        (
            "Autonomous agent built on Google ADK, Gemini 3.1 Pro, and Vertex AI Agent Engine "
            "(Reasoning Engine ID 519268830350934016).\n\n"
            "Executes parallel discovery across the entire GCP Organization in ~6.7 seconds, mapping Cloud KMS/HSM, "
            "workloads via Cloud Asset Inventory (4 vectors), SSL/TLS 1.3 policies, and KMS ImportJobs.\n\n"
            "Automatically exports OWASP CycloneDX v1.6 CBOM, Monte Carlo Q-VaR (95%) simulation, and HSM runbooks."
        ),
    )
    set_shape_text("g3868b008361_2_1020", "Customer Value")
    set_shape_text(
        "g3868b008361_2_1021",
        (
            "Compresses cryptographic discovery from 4 weeks to under 7 seconds.\n"
            "Quantifies financial quantum exposure (Q-VaR 95%: US$ 10.32M mitigated to US$ 0.15M).\n"
            "Prevents production outages from 3,309-byte ML-DSA signatures and KEM Decapsulate API transitions.\n"
            "Generates copy-pasteable 5-step gcloud HSM commands and Google Tink SDK refactoring patterns.\n"
            "Ensures continuous compliance with NIST FIPS 203/204/205 and preventive GCP Org Policies."
        ),
    )

    # --- Slide [45] (g601861432e1ca7c6_5258): 4-Layer Discovery Architecture (3x4 Table) ---
    set_shape_text("g601861432e1ca7c6_5285", "4-Layer Cryptographic Discovery")
    t45 = "g601861432e1ca7c6_5265"
    cols_t45 = [
        (
            "Layer 1: Data-at-Rest",
            "Cloud KMS, Cloud HSM & EKM",
            "Evaluates all key rings, RSA/ECC/AES algorithms, and HSM protection levels against Shor and Grover (<=90d rotation).",
        ),
        (
            "Layer 2: Blast Radius",
            "4-Vector CAI Workload Mapping",
            "Correlates every KMS key to live workloads (BigQuery, GCS, GKE, Cloud SQL, Spanner) and IAM Service Accounts.",
        ),
        (
            "Layer 3: Data-in-Transit",
            "TLS 1.3 (X25519MLKEM768) & CAS",
            "Inspects Compute SslPolicies and L7 Load Balancers to enable hybrid post-quantum key exchange and CAS PKI.",
        ),
        (
            "Layer 4: BYOK Chain",
            "KMS ImportJobs Audit",
            "Identifies external keys imported with vulnerable classical RSA-OAEP wrapping and guides quantum-safe HPKE import.",
        ),
    ]
    for ci, (r0, r1, r2) in enumerate(cols_t45):
        set_table_cell_text(t45, 0, ci, r0)
        set_table_cell_text(t45, 1, ci, r1)
        set_table_cell_text(t45, 2, ci, r2)

    # --- Slide [43] (g601861432e1ca7c6_5236): Quantum Physics & ADK Engine (orig len=1322) ---
    set_shape_text("g601861432e1ca7c6_5237", "Quantum Physics Engine & Q-VaR Simulation")
    set_shape_text(
        "g601861432e1ca7c6_5239",
        (
            "1. Shor's Factoring for RSA (Gidney & Ekerå 2021): Computes 2n + 3 logical qubits and surface code distance d=27 (~20 million physical qubits break RSA-2048 in ~8 hours).\n"
            "2. Elliptic Curve Discrete Log — ECDLP (Roetteler et al. 2017): Proves mathematically that ECDSA P-256 keys (~2,330 logical qubits) fall BEFORE RSA-2048 (4,099 logical qubits), requiring P0 priority.\n"
            "3. Grover's Quantum Search (NIST SP 800-57): Validates post-quantum resilience of symmetric AES-256 keys (128 effective bits) and flags rotation neglect (>90 days) or non-quantum-safe HMAC-SHA1.\n"
            "4. Core-SVP Lattice Hardness (NIST FIPS 203 & 204): Validates exponential 2^(0.265*b) complexity for ML-KEM-768 (182-bit) and ML-DSA-65 (166-bit) standards.\n"
            "5. Monte Carlo Q-VaR 95% Simulation (10,000 Runs): Models stochastic CRQC arrival against Mosca's Theorem (X + Y > Z), reducing financial exposure from US$ 10.32M to US$ 0.15M (-98.5%)."
        ),
    )

    # --- Slide [40] (g601861432e1ca7c6_1995): Validated Scorecard & Benchmark Table (6x2) ---
    set_shape_text("g601861432e1ca7c6_3343", "Validated Scorecard — Org 31564119954")
    set_shape_text("g601861432e1ca7c6_2000", "Verified Live Telemetry")
    t40 = "g601861432e1ca7c6_1998"
    set_table_cell_text(t40, 0, 0, "Cryptographic Domain / KPI", had_text=False)
    set_table_cell_text(t40, 0, 1, "Validated Result & Recommended Action", had_text=False)
    rows_t40 = [
        ("Weighted PQC Maturity", "70.0% (MODERATE) — 52 assets and 22 workloads mapped in 6.71s."),
        ("Asymmetric Migration (Shor)", "50.0% — Migrate ECDSA P-256 and RSA-2048 to ML-DSA-65 and KEM_XWING."),
        ("Symmetric AES-256 Hygiene", "100% Grover-resilient | 66.7% meeting <= 90-day active rotation SLA."),
        ("TLS 1.3 Network Edge & BYOK", "50.0% — Upgrade SslPolicies to TLS 1.3 MODERN (X25519MLKEM768)."),
        ("Quantum Value-at-Risk (95%)", "US$ 10.32 Million unmitigated -> US$ 0.15 Million post-PQC migration."),
    ]
    for ri, (k_col, v_col) in enumerate(rows_t40, start=1):
        set_table_cell_text(t40, ri, 0, k_col)
        set_table_cell_text(t40, ri, 1, v_col)

    # --- Slide [35] (g3bfa828a128_2_5004): 2-Column Consultative Runbooks & Refactoring ---
    set_shape_text("g3bfa828a128_2_5011", "Consultative Execution & Refactoring")
    set_shape_text("g3bfa828a128_2_5006", "5-Step Per-Key Runbook (HSM)")
    set_shape_text("g3bfa828a128_2_5007", "Prescriptive guide generated for 100% of discovered vulnerable keys.")
    set_shape_text(
        "g3bfa828a128_2_5005",
        (
            "1. Cloud KMS / HSM Provisioning\n"
            "Creates PQ_SIGN_ML_DSA_65 and KEM_XWING keys with FIPS-validated protection.\n\n"
            "2. Least-Privilege IAM Replication\n"
            "Preserves workload Service Account bindings with zero downtime.\n\n"
            "3. Canary Cutover & Verification\n"
            "Dual-signing rollout and safe disablement of legacy key versions."
        ),
    )
    set_shape_text("g3bfa828a128_2_5008", "Code & Gateway Refactoring")
    set_shape_text("g3bfa828a128_2_5009", "Prevents production outages when transitioning from RSA/ECC to PQC.")
    set_shape_text(
        "g3bfa828a128_2_5010",
        (
            "Google Tink SDK (Envelope Encryption)\n"
            "Abstracts the transition from AsymmetricDecrypt() to KEM Decapsulate().\n\n"
            "HTTP/JWT Header Tuning (16KB-32KB)\n"
            "Accommodates 3,309-byte ML-DSA-65 signatures in Envoy/NGINX.\n\n"
            "GCP Org Policy Guardrails\n"
            "Blocks creation of new classical RSA/ECC keys."
        ),
    )

    # --- Slide [36] (g3bfa828a128_2_5014): 3-Step Engagement Roadmap ---
    set_shape_text("g3bfa828a128_2_5023", "Consultative PQC Engagement Roadmap")
    set_shape_text(
        "g3bfa828a128_2_5022",
        (
            "Phase 1: 7s Discovery & CBOM (Week 1)\n"
            "Read-only scan across the GCP Organization, CycloneDX v1.6 CBOM generation, and Q-VaR 95% modeling."
        ),
    )
    set_shape_text(
        "g3bfa828a128_2_5019",
        (
            "Phase 2: Architecture & Hybrid Pilot (Weeks 2-3)\n"
            "Google Tink SDK refactoring workshops, gateway header tuning for ML-DSA-65, and TLS 1.3 X25519MLKEM768."
        ),
    )
    set_shape_text(
        "g3bfa828a128_2_5021",
        (
            "Phase 3: Cloud HSM Cutover & Governance (Weeks 4-6)\n"
            "Execution of 5-step remediation runbooks and enforcement of preventive GCP Organization Policies."
        ),
    )

    # --- Slide [42] (g601861432e1ca7c6_3876): Commercial Impact & GCP Pull-Through ---
    set_shape_text("g601861432e1ca7c6_5251", "Commercial Impact\n& GCP Consumption")
    set_shape_text("g601861432e1ca7c6_5252", "Why We Win\nwith Google Cloud")
    set_shape_text(
        "g601861432e1ca7c6_5256",
        (
            "High-margin delivery accelerator for GCC and direct GCP consumption pull-through:\n"
            "Compresses discovery and runbook engineering effort from 120-160 hours to under 5 minutes (-85%).\n"
            "Converts cryptographic gaps into immediate expansion of the Google Cloud security stack."
        ),
    )
    set_shape_text(
        "g601861432e1ca7c6_5257",
        "*Aligned with NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NIST IR 8547 & EO 14412.",
    )
    set_shape_text(
        "g3c4484cac3e_1_1",
        (
            "1. Cloud HSM (FIPS 140-3 Level 3) & Cloud KMS PQC: Immediate adoption of post-quantum keys (PQ_SIGN_ML_DSA_65, KEM_XWING, and ML-KEM-768) and HPKE quantum-safe import.\n"
            "2. Google Cloud Global Load Balancing (L7) & Certificate Authority Service (CAS): Edge termination with hybrid TLS 1.3 key exchange (X25519MLKEM768) and automated short-lived mTLS PKI.\n"
            "3. VPC Service Controls (VPC-SC), Private Service Connect & Binary Authorization: Zero-trust perimeters against HNDL exfiltration and post-quantum container signing on GKE and Cloud Run."
        ),
    )
    set_shape_text("g601861432e1ca7c6_5284", "From cryptographic visibility to end-to-end modernization on Google Cloud.")

    # --- Slide [78] (g3868b008361_2_7841): Multi-Persona Deliverables & Runtime Ecosystem ---
    set_shape_text(
        "g3868b008361_2_7843",
        (
            "The Agentic PQC Readiness & CBOM Engine is deployed in production on Vertex AI Agent Engine "
            "and Cloud Run, automatically generating 4 executive and technical deliverable packages:"
        ),
    )
    set_shape_text("g3868b008361_2_7848", "Automatically generated deliverables:")
    set_shape_text("g3868b008361_2_7844", "01. Executive Board & CISO Report (Scorecard & Q-VaR)")
    set_shape_text("g3868b008361_2_7845", "02. Technical Engineering Playbook (5-Step HSM Runbooks)")
    set_shape_text("g3868b008361_2_7846", "03. OWASP CycloneDX v1.6 CBOM (.json) with Official NIST OIDs")
    set_shape_text("g3868b008361_2_7847", "04. GCP Org Policy YAML & Google Tink SDK Refactoring Bundle")
    set_shape_text("g3868b008361_2_7849", "Key operational differentiators:")
    set_shape_text(
        "g3868b008361_2_7850",
        "Deterministic Telemetry Validation (LIVE_GCP_TELEMETRY_VERIFIED) with zero mathematical hallucination.",
    )
    set_shape_text(
        "g3868b008361_2_7851",
        "Automatic redirection from internal Vertex AI tenant projects (*-tp) to the customer's real GCP Organization.",
    )
    set_shape_text(
        "g3868b008361_2_7852",
        "Ready for execution via Gemini Enterprise, Cloud Run Web UI, or CLI across any Google Cloud customer.",
    )

    # --- Slide [83] (g3868b008361_2_7962): Closing Slide ---
    set_shape_text("g3868b008361_2_7964", "Thank You")

    # Translate layout footer shapes from Portuguese to English
    for footer_oid in ("g3868b008361_2_8665", "g3c5e30c5cde_1_818", "g3ba1617fda0_0_1475"):
        set_shape_text(footer_oid, "Proprietary + Confidential")

    api_json(
        "POST",
        f"https://slides.googleapis.com/v1/presentations/{pres_id}:batchUpdate",
        token,
        body={"requests": reqs},
    )

    return {
        "id": pres_id,
        "name": target_name,
        "webViewLink": cloned.get("webViewLink", f"https://docs.google.com/presentation/d/{pres_id}/edit"),
    }


DOCUMENTS_SPEC = [
    # -------------------------------------------------------------------------
    # 01. SOW Template — COMPREHENSIVE 6-WEEK PSO STATEMENT OF WORK TEMPLATE
    # -------------------------------------------------------------------------
    {
        "doc_name": "SOW_PQC_Readiness_Assessment_Template",
        "old_names": ["01_SOW_PQC_Readiness_Assessment_Template.md", "01_SOW_PQC_Readiness_Assessment_Template"],
        "cover_title": "Post-Quantum Cryptography\u000bStatement of Work (SOW)",
        "cover_subtitle": "Google Cloud Consulting (PSO) — 6-Week PQC Readiness Assessment & Migration Advisory Template",
        "page2_headline": "Statement of Work (SOW): 6-Week PQC Readiness Assessment & Advisory",
        "page2_subtitle": "Contractual Scope, 6-Week Work Breakdown Structure (WBS), Deliverables, RACI & Governance Model Powered by the Agentic PQC Readiness Engine",
        "exec_summary": (
            "This Statement of Work (SOW) template defines the contractual scope, 6-week Work Breakdown Structure (WBS), "
            "deliverables, acceptance criteria, RACI matrix, and governance model for a Google Cloud Consulting — "
            "Professional Services Organization (PSO) Post-Quantum Cryptography (PQC) Readiness Assessment and Migration "
            "Advisory engagement. By pairing senior PSO Security Architects with the Agentic PQC Readiness & CBOM Engine, "
            "Google Cloud compresses cryptographic discovery and mathematical risk modeling into Weeks 1–3, dedicating "
            "Weeks 4–6 to high-value architecture workshops, application refactoring, non-production Cloud HSM cutover "
            "validation, and preventive GCP Organization Policy guardrails."
        ),
        "blocks": [
            ("H2", "1. Engagement Identification & Customer Environment Parameterization"),
            ("P", "This Statement of Work (\"SOW\") is entered into between Google Cloud Consulting — Professional Services Organization (\"Google Cloud PSO\") and Customer (<CUSTOMER_LEGAL_NAME>) to execute a 6-week Consultative Post-Quantum Cryptography (PQC) Readiness Assessment and Migration Advisory across the Customer's designated Google Cloud estate. Populate the engagement parameters below prior to contract execution:"),
            ("TABLE", [
                ["Contractual / Technical Parameter", "Placeholder / Config Token", "Expected Value / Selection Options", "Customer Contracted Value (Populate at SOW Signing)"],
                ["Customer Legal Entity Name", "<CUSTOMER_LEGAL_NAME>", "Full legal entity name of the contracting organization", "[ Leave Blank — Populate for Customer ]"],
                ["Primary Regulated Industry Vertical", "<SECTOR_CODE>", "BFSI_BANKING | HEALTHCARE_GENOMICS | PUBLIC_SECTOR_DEFENSE | TELECOM_5G_CLOUD | ENERGY_OT_INDUSTRIAL", "[ Leave Blank — Populate for Customer ]"],
                ["In-Scope GCP Organization ID(s)", "<CUSTOMER_ORG_ID>", "organizations/<12_DIGIT_ORG_ID> (plus designated folder/project scopes)", "[ Leave Blank — Populate for Customer ]"],
                ["Engagement Sizing Tier & Duration", "<SIZING_TIER>", "Standard Enterprise Tier — 6 Calendar Weeks (30 Business Days)", "6 Calendar Weeks (Weeks 1 to 6)"],
                ["Selected Agent Deployment Topology", "<DEPLOYMENT_TOPOLOGY>", "Topology A (Customer Cloud Run + VPC-SC) | Topology B (Cross-Org SA Impersonation) | Topology C (Workstation)", "[ Leave Blank — Populate for Customer ]"],
                ["Customer Host Project & Agent Endpoint", "<CUSTOMER_HOST_PROJECT_ID>", "Host Project ID / Cloud Run URL / Vertex AI Agent Engine URI", "[ Leave Blank — Populate in Customer Environment ]"],
                ["Customer Executive Sponsor & CISO POC", "<CUSTOMER_SPONSOR_NAME>", "Name, Title, Email of CISO / VP of Security / Head of Cloud Platform", "[ Leave Blank — Populate for Customer ]"],
            ]),
            ("H2", "2. Strategic Objectives, Regulatory Drivers & Consultative Positioning"),
            ("P", "Customer has engaged Google Cloud PSO to establish an empirical, cryptographically verified baseline of its Google Cloud estate and engineer a phased migration roadmap toward Post-Quantum Cryptography (PQC). This engagement directly addresses the technical, operational, and financial imperatives introduced by:"),
            ("BULLETS", [
                "NIST Post-Quantum Cryptography Standards: Federal Information Processing Standards FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism: ML-KEM-512/768/1024 and hybrid X-Wing), FIPS 204 (Module-Lattice-Based Digital Signature Standard: ML-DSA-44/65/87), and FIPS 205 (Stateless Hash-Based Digital Signature Standard: SLH-DSA).",
                "Global Deprecation Mandates & Executive Directives: NIST IR 8547 (Final, October 2026) establishing the mandatory 2030 deprecation and 2035 disallowance of classical RSA-2048/3072/4096, ECDSA, and ECDH (P-256/P-384/P-521); White House Executive Order 14412 & OMB Memoranda M-23-02 / M-26-15 requiring automated Cryptographic Bills of Materials (CBOM); NSA CNSA 2.0; UK NCSC (2028/2031/2035 milestones); and sector frameworks (PCI-DSS v4.0.1, DORA, BACEN BCB 85/4893, HIPAA).",
                "Harvest-Now, Decrypt-Later (HNDL) & Breaking-Change Mitigation: Neutralizing passive adversary interception of long-lived ciphertexts where Mosca's Theorem (X + Y > Z) is violated, while engineering safe application transitions across KEM API shifts (Decrypt -> Encapsulate/Decapsulate) and signature payload bloat (64B ECDSA -> 3,309B ML-DSA-65).",
                "Consultative Engineering Advisory (Non-Audit Positioning): Google Cloud PSO performs a deep Consultative PQC Readiness Assessment, Control-Plane Posture Verification, and Engineering Migration Advisory. Google Cloud PSO does not act as a statutory, regulatory, or financial auditor, nor does this engagement constitute a formal compliance certification or legal opinion.",
            ]),
            ("H2", "3. Detailed 6-Week Work Breakdown Structure (WBS) & Execution Plan"),
            ("P", "The engagement is structured across four logical delivery phases executed over six (6) consecutive calendar weeks. By leveraging the Agentic PQC Readiness & CBOM Engine (detailed in PQC_System_Architecture_Specification and PQC_Technical_Design_Document_TDD), automated telemetry collection and mathematical modeling are completed rapidly in Weeks 1–3, enabling deep architectural and hands-on engineering workshops in Weeks 4–6:"),
            ("TABLE", [
                ["Week & Phase", "Primary Focus Area", "Key PSO & Agentic Activities", "Weekly Outputs & Exit Criteria"],
                ["Week 1 (Phase 1A)", "Mobilization, IAM Onboarding & 7-Domain Calibration", "Deliver Executive Kickoff (PQC_Kickoff_Engagement_Deck); configure least-privilege read-only IAM or deploy Agentic PQC Engine (PQC_User_and_Consultant_Guide); conduct 7-Domain Stakeholder Discovery Workshops (PQC_Discovery_Questionnaire); execute calibrate_assessment_context.", "Validated GCP read-only telemetry access; scored 7-Domain Maturity Rubric (Levels 1-5); locked Sector Calibration Profile in calibration_history.jsonl."],
                ["Week 2 (Phase 1B & 2A)", "Automated 4-Vector GCP Discovery & Blast-Radius Correlation", "Execute discover_gcp_kms_inventory and compute_quantum_risk_posture across Cloud KMS/HSM, Cloud Asset Inventory (4-Vector workload correlation across GKE, Cloud SQL, BigQuery, GCS, Compute), Compute SSL/TLS policies, CAS PKI, and BYOK ImportJobs; resolve -tp tenant sandboxes.", "100% in-scope GCP cryptographic inventory correlated to downstream workloads; baseline OWASP CycloneDX v1.6 CBOM JSON generated."],
                ["Week 3 (Phase 2B)", "Quantum Physics Modeling, Mosca (X+Y>Z) & Monte Carlo Q-VaR", "Run Shor (Gidney & Ekera 2021), Roetteler ECDLP (2017), Grover, and Core-SVP circuit modeling; evaluate Mosca's Theorem (X + Y > Z) per business unit; execute 10,000-iteration Monte Carlo Q-VaR (95%) financial simulation in USD; hold Mid-Engagement Risk Review with CISO.", "Validated Quantum Vulnerability Heatmap, Mosca HNDL Overdue Matrix, and calibrated Q-VaR (95%) financial exposure model signed off."],
                ["Week 4 (Phase 3A)", "Edge TLS 1.3 (X25519MLKEM768), CAS PKI & Network Perimeter Design", "Conduct architecture workshops with Network, SRE, and PKI teams; design hybrid TLS 1.3 (X25519MLKEM768) policies on Cloud Load Balancing (L7) & Service Mesh; evaluate 1,120B KEM TCP initcwnd impact; design CAS PQC dual-root PKI and VPC-SC HNDL exfiltration perimeters.", "Target-State Edge TLS 1.3 & CAS PKI Architecture Blueprint; VPC Service Controls (VPC-SC) HNDL containment design."],
                ["Week 5 (Phase 3B)", "Application Crypto Agility, Tink SDK Refactoring & Non-Prod HSM Pilot", "Conduct developer & IAM workshops on KEM refactoring (AsymmetricDecrypt -> Google Tink SDK KEM_XWING / ML-KEM-768 + AES-256-GCM DEK), JWT header bloat mitigation (3,309B ML-DSA-65 on Envoy/Apigee 16KB-32KB buffers), Binary Authorization signing, and execute a guided 5-step Cloud HSM PQC key rotation pilot in non-production.", "Validated Non-Production Cloud HSM PQC Key Cutover Pilot; completed Technical Engineering Playbook with 5-step per-key runbooks."],
                ["Week 6 (Phase 4)", "Preventive Org Policy Guardrails, Multi-Year Roadmap & Board Closeout", "Deliver preventive GCP Organization Policy YAML constraints (enforcing HSM protection levels and blocking legacy RSA/ECC creation post-cutover); finalize CISO Strategic Recommendations Book and 2026-2035 Migration Roadmap; conduct Executive Board & CISO Closeout Presentation.", "Complete 6-Deliverable Handover Package accepted; formal Deliverable Acceptance Form signed."],
            ]),
            ("H3", "3.1 Week 1 (Phase 1A): Mobilization, IAM Onboarding & 7-Domain Sector Calibration"),
            ("BULLETS", [
                "Executive & Technical Kickoff: Deliver the formal engagement kickoff presentation (aligned with PQC_Kickoff_Engagement_Deck) to align executive sponsors, security architects, PKI owners, and platform leads on the 6-week schedule, milestones, and governance cadence.",
                "Non-Intrusive Read-Only IAM & Runtime Onboarding: Provision the four least-privilege read-only GCP IAM roles (roles/cloudasset.viewer, roles/cloudkms.viewer, roles/privateca.auditor, and roles/compute.viewer) at the target GCP Organization scope (organizations/<CUSTOMER_ORG_ID>) and deploy or connect the Agentic PQC Readiness Engine using the selected deployment topology (Topology A, B, or C per PQC_User_and_Consultant_Guide).",
                "7-Domain Stakeholder Discovery & Posture Verification Workshops: Facilitate structured interviews across all seven weighted domains of the PQC_Discovery_Questionnaire: (1) Data Confidentiality Shelf-Life (X) & HNDL Exposure, (2) KMS/HSM/BYOK & Root PKI, (3) Edge L7 Load Balancers & TLS/mTLS Service Mesh, (4) Application Cryptographic Agility & Tink SDKs, (5) Identity/IAM & JWT/OIDC Header Sizing, (6) CI/CD Supply Chain & Binary Authorization, and (7) Third-Party SaaS & Inter-Cloud Interconnects.",
                "Agent Context & Sector Calibration: Score the 35-question maturity rubric (Levels 1.0 to 5.0) and execute calibrate_assessment_context to persist the Customer's industry sector profile, Mosca X and Y horizons, and compensating controls into calibration_history.jsonl.",
                "Week 1 Exit Criteria: Read-only GCP telemetry access verified; 7-Domain Discovery Questionnaire completed and scored; Customer Sector Calibration Profile locked.",
            ]),
            ("H3", "3.2 Week 2 (Phase 1B & Phase 2A): Automated 4-Vector GCP Discovery & Blast-Radius Correlation"),
            ("BULLETS", [
                "Vector 1 — Cloud KMS, Cloud HSM & EKM Inventory: Execute discover_gcp_kms_inventory across all in-scope GCP folders and projects to enumerate every KeyRing, CryptoKey, primary CryptoKeyVersion, algorithm family, protection level (SOFTWARE, HSM, EXTERNAL), rotation schedule, and ImportJob wrapping method.",
                "Vector 2 — Cloud Asset Inventory 4-Vector Workload Blast-Radius Correlation: Correlate every discovered KMS key against downstream GCP resources across (a) Direct CMEK infrastructure bindings, (b) GKE cluster boot-disk and application-layer Secrets encryption, (c) Cloud SQL, AlloyDB, Spanner, BigQuery, and Cloud Storage data stores, and (d) Pub/Sub, Secret Manager, and Artifact Registry pipelines.",
                "Vector 3 & Vector 4 — Edge SSL/TLS Policies, CAS PKI & Tenant Sandbox Resolution: Inspect Compute Engine SSL/TLS policies (minimum TLS versions and cipher profiles), Certificate Authority Service (CAS) root/subordinate CA algorithms, and automatically resolve Google-managed tenant projects (-tp suffix) to parent projects.",
                "Baseline CycloneDX v1.6 CBOM Generation: Execute generate_cyclonedx_cbom to compile the machine-readable OWASP CycloneDX v1.6 JSON Cryptographic Bill of Materials mapped to official NIST Object Identifiers (OIDs).",
                "Week 2 Exit Criteria: 100% of in-scope GCP cryptographic assets inventoried, correlated to downstream application workloads, classified by project tier (PROD / NON-PROD / SANDBOX), and exported to CycloneDX v1.6 CBOM.",
            ]),
            ("H3", "3.3 Week 3 (Phase 2B): Quantum Physics Modeling, Mosca (X+Y>Z) & Monte Carlo Q-VaR Quantification"),
            ("BULLETS", [
                "Surface-Code Quantum Circuit Modeling: Execute calculate_quantum_circuit_metrics using peer-reviewed cryptanalytic models—Gidney & Ekera (2021) for RSA factoring (4,098 logical qubits / ~5.97M physical qubits for RSA-2048), Roetteler et al. (2017) for Elliptic Curve Discrete Logarithms (2,330 logical qubits / ~3.40M physical qubits for ECDSA/ECDH P-256), Albrecht Core-SVP for lattice primitives, and Grassl et al. (2016) for Grover symmetric search.",
                "Mosca's Theorem (X + Y > Z) HNDL Horizon Analysis: Combine the Customer's calibrated confidentiality shelf-life (X) and migration duration (Y) against empirical CRQC arrival horizons (Z) to pinpoint every business domain and dataset currently in active Harvest-Now, Decrypt-Later (HNDL) violation.",
                "10,000-Iteration Monte Carlo Quantum Value-at-Risk (Q-VaR 95%) Simulation: Execute simulate_monte_carlo_qvar incorporating the Customer's sector regulatory multiplier, data volume, and breach cost baselines to quantify the 95th-percentile financial exposure in USD.",
                "Mid-Engagement CISO & Risk Committee Checkpoint: Present the validated Quantum Vulnerability Heatmap, Mosca HNDL Overdue Matrix, and Q-VaR (95%) financial model to the CISO and Enterprise Risk Management (ERM) stakeholders to prioritize Weeks 4–5 engineering focus.",
                "Week 3 Exit Criteria: Quantum Vulnerability Heatmap, Mosca HNDL Overdue Matrix, and Monte Carlo Q-VaR (95%) financial model formally reviewed and signed off by Security Leadership.",
            ]),
            ("H3", "3.4 Week 4 (Phase 3A): Edge TLS 1.3 (X25519MLKEM768), CAS PKI & Network Perimeter Workshops"),
            ("BULLETS", [
                "Hybrid Post-Quantum TLS 1.3 Edge Architecture: Lead technical design workshops with Network and SRE teams to configure hybrid post-quantum key exchange (X25519MLKEM768) on Google Cloud Global External Application Load Balancers (L7), Cloud Armor, and GKE Service Mesh (Istio/Envoy).",
                "Network MTU & TCP Initial Congestion Window (initcwnd) Engineering: Analyze the wire-format impact of 1,120-byte X25519MLKEM768 client/server key shares and 3,309-byte ML-DSA-65 certificate signatures across middleboxes, deep-packet inspection (DPI) firewalls, and TCP initcwnd budgets.",
                "Certificate Authority Service (CAS) Dual-Root / Cross-Signed PKI Blueprint: Design the phased migration from classical RSA/ECDSA internal CAs to FIPS 204 (ML-DSA-65) and FIPS 205 (SLH-DSA) hierarchies with automated short-lived certificate issuance via cert-manager.",
                "VPC Service Controls (VPC-SC) HNDL Exfiltration Containment: Architect zero-trust VPC-SC service perimeters, Private Service Connect (PSC) endpoints, and ingress/egress rules around high-value data repositories (BigQuery, GCS, Cloud SQL) to block bulk ciphertext exfiltration.",
                "Week 4 Exit Criteria: Target-State Edge TLS 1.3 (X25519MLKEM768), CAS PQC PKI, and VPC-SC HNDL Containment Architecture Blueprint completed.",
            ]),
            ("H3", "3.5 Week 5 (Phase 3B): Application Crypto Agility, Tink SDK Refactoring & Non-Prod Cloud HSM Pilot"),
            ("BULLETS", [
                "KEM API Contract Refactoring Workshop (Decrypt -> Encapsulate/Decapsulate + HPKE): Guide Application Architects through refactoring direct Cloud KMS AsymmetricDecrypt calls into RFC 9180 Hybrid Public Key Encryption (HPKE) and Google Tink SDK hybrid envelope encryption using KEM_XWING / ML-KEM-768 Key-Encryption Keys (KEKs) and AES-256-GCM Data-Encryption Keys (DEKs).",
                "Identity, OIDC/SAML & JWT Header Bloat Mitigation Workshop: Evaluate the 51x signature expansion from ECDSA P-256 (64 bytes) to ML-DSA-65 (3,309 bytes / ~4.4 KB in Base64URL JWTs); specify HTTP header buffer upgrades (16KB–32KB) for Envoy, NGINX, and Apigee API Gateways alongside Phantom Token / Reference Token architectural patterns.",
                "CI/CD Software Supply Chain & Binary Authorization Signing: Design post-quantum artifact and container image signing pipelines using Cloud KMS PQ_SIGN_ML_DSA_65 keys integrated with Binary Authorization on GKE and Cloud Run.",
                "Guided Non-Production Cloud HSM PQC Cutover Lab: Execute a live, non-disruptive 5-step PQC key rotation pilot in the Customer's designated non-production GCP project—provisioning FIPS 140-3 Level 3 Cloud HSM keys (pq-sign-ml-dsa-65 and kem-xwing), replicating IAM bindings, validating dual-stack signing/encapsulation, and compiling per-key runbooks.",
                "Week 5 Exit Criteria: Non-Production Cloud HSM PQC Key Cutover Pilot successfully validated; Technical Engineering Playbook with 100% per-key 5-step runbooks generated.",
            ]),
            ("H3", "3.6 Week 6 (Phase 4): Preventive Org Policy Guardrails, Multi-Year Roadmap & Executive Board Closeout"),
            ("BULLETS", [
                "Preventive GCP Organization Policy Guardrail Engineering: Deliver and validate declarative GCP Organization Policy YAML constraints—including constraints/cloudkms.allowedProtectionLevels (enforcing HSM protection levels) and custom constraints prohibiting new classical RSA_SIGN_*, RSA_DECRYPT_*, and EC_SIGN_* key creation in migrated production folders.",
                "CISO Strategic Recommendations Book & Multi-Year Roadmap (2026–2035): Finalize the phased migration roadmap (Phase 1 Immediate 0–6 Months, Phase 2 Near-Term 6–18 Months, Phase 3 Long-Term 18–36+ Months toward 2030 NIST deprecation) and the Google Cloud Security Architecture Bill of Materials (BOM).",
                "Executive Board & CISO Closeout Presentation: Deliver the formal closeout readout to the CISO, CIO, CFO, and Architecture Review Board, walking through the validated maturity score, Q-VaR reduction trajectory, and operational handover.",
                "Final 6-Deliverable Handover & Engagement Sign-Off: Transfer all six contractual deliverables into the Customer's designated repository and execute the formal Deliverable Acceptance Sign-Off.",
                "Week 6 Exit Criteria: All six contractual deliverables (D-01 through D-06) delivered and formally accepted; Executive Board Closeout completed.",
            ]),
            ("H2", "4. Contractual Deliverables & Acceptance Criteria Matrix"),
            ("P", "Google Cloud PSO will deliver six (6) formal engagement artifacts. All deliverables are produced in fluent English and grounded in the Customer's live GCP telemetry and calibrated stakeholder workshops:"),
            ("TABLE", [
                ["ID", "Deliverable Name", "Delivery Week & Target Audience", "Core Contents & Objective Acceptance Criteria"],
                ["D-01", "Calibrated 7-Domain Discovery & Maturity Baseline", "Week 1 — CISO, GRC, Enterprise Security Architects", "Completed 35-question PQC_Discovery_Questionnaire scorecard (Levels 1.0–5.0 across 7 domains), sector calibration ledger (calibration_history.jsonl), and validated Mosca X and Y parameters."],
                ["D-02", "OWASP CycloneDX v1.6 CBOM & 4-Vector Inventory", "Week 2 — GRC, SecOps, KMS & PKI Owners", "Machine-readable CycloneDX v1.6 JSON CBOM plus human-readable inventory covering 100% of in-scope GCP KMS/HSM keys, TLS policies, CAS CAs, and 4-Vector workload dependencies with NIST OIDs."],
                ["D-03", "Executive Board PQC Readiness & Q-VaR Report", "Week 3 / Week 6 — CEO, CFO, CISO, Board of Directors", "C-Level BLUF, Validated PQC Maturity Score (0-100%), surface-code qubit metrics, Mosca HNDL Overdue Matrix, 10k Monte Carlo Q-VaR (95%) in USD, and Google Cloud Security Architecture BOM."],
                ["D-04", "Edge TLS 1.3 (X25519MLKEM768) & CAS PKI Blueprint", "Week 4 — Network, SRE, Load Balancer & PKI Owners", "Target-state architecture for L7 Load Balancer & Service Mesh hybrid TLS 1.3 (X25519MLKEM768), TCP initcwnd tuning, CAS dual-root ML-DSA-65/SLH-DSA hierarchy, and VPC-SC HNDL perimeters."],
                ["D-05", "Technical Engineering Playbook & 5-Step HSM Runbooks", "Week 5 — Cloud Engineers, IAM Leads, App Developers", "Individual 5-step Cloud HSM rotation runbooks for 100% of vulnerable keys, IAM replication scripts, Google Tink SDK KEM/HPKE refactoring templates, Envoy/Apigee 16KB-32KB JWT configs, and non-prod pilot logs."],
                ["D-06", "Preventive GCP Org Policy Bundle & CISO Roadmap Book", "Week 6 — Cloud Governance, CISO & Security Leadership", "Declarative GCP Organization Policy YAML constraints blocking legacy RSA/ECC creation and enforcing Cloud HSM, paired with the CISO Strategic Recommendations Book and 2026–2035 Migration Roadmap."],
            ]),
            ("H2", "5. Engagement Team Structure, Resource Allocation & RACI Matrix"),
            ("P", "Successful completion within the 6-week timeline relies on a dedicated Google Cloud PSO delivery pod working alongside Customer subject matter experts (SMEs). The tables below define the PSO specialist roles, weekly effort allocation, and the Responsibility Assignment Matrix (R = Responsible, A = Accountable, C = Consulted, I = Informed):"),
            ("TABLE", [
                ["Role Title", "Organization", "Primary Responsibilities Across the 6-Week Engagement", "Estimated Allocation"],
                ["Principal PQC Security Architect (Lead)", "Google Cloud PSO", "Leads kickoff, 7-domain calibration, quantum cryptanalysis/Q-VaR modeling, Edge TLS/PKI architecture workshops, CISO roadmap, and Board readout.", "Weeks 1–6 (Full Engagement Lead)"],
                ["Cloud Infrastructure, KMS & App Crypto Specialist", "Google Cloud PSO", "Executes Agentic PQC Engine deployment, 4-Vector CBOM discovery, Tink SDK/JWT refactoring workshops, Week 5 Cloud HSM pilot, and Org Policy YAML engineering.", "Weeks 1–6 (Hands-On Engineering)"],
                ["Engagement Manager / Project Director", "Google Cloud PSO", "Manages 6-week WBS governance, weekly steering syncs, stakeholder scheduling, risk tracking, and formal Deliverable Acceptance sign-offs.", "Weeks 1–6 (Governance & PMO)"],
                ["Executive Sponsor / CISO & Risk Lead", "Customer", "Approves engagement scope, validates Mosca confidentiality horizons (X) and Q-VaR risk appetite, chairs Week 3/Week 6 readouts, and signs Deliverable Acceptance.", "Weeks 1, 3, 6 (Executive Checkpoints)"],
                ["Cloud Platform, KMS/PKI, Network & App SMEs", "Customer", "Provisions read-only IAM roles (Days 1–3), participates in Week 1 calibration and Weeks 4–5 workshops, and co-executes the Week 5 non-prod Cloud HSM pilot.", "2–4 Hours / Week (Workshops & Lab)"],
            ]),
            ("H3", "5.1 Workstream Responsibility Assignment Matrix (RACI)"),
            ("TABLE", [
                ["Engagement Workstream / Weekly Milestone", "Google PSO Lead Architect", "Google PSO KMS & App Specialist", "Customer CISO / Exec Sponsor", "Customer Cloud / IAM / PKI SMEs"],
                ["Week 1: Kickoff, Read-Only IAM Provisioning & Agent Deployment", "R", "C", "A", "R"],
                ["Week 1: 7-Domain Stakeholder Discovery & Mosca (X, Y) Calibration", "R", "C", "A", "R"],
                ["Week 2: Automated 4-Vector GCP Discovery & CycloneDX v1.6 CBOM", "A", "R", "I", "C"],
                ["Week 3: Quantum Circuit Modeling & Monte Carlo Q-VaR (95%) Simulation", "R", "R", "A", "C"],
                ["Week 4: Edge TLS 1.3 (X25519MLKEM768), CAS PKI & VPC-SC Design", "R", "C", "I", "R"],
                ["Week 5: Tink SDK KEM/JWT Refactoring & Non-Prod Cloud HSM Pilot", "C", "R", "I", "R"],
                ["Week 6: Preventive GCP Org Policies & Executive Board Closeout", "R", "C", "A", "C"],
            ]),
            ("H2", "6. Out-of-Scope Boundaries & Engagement Assumptions"),
            ("P", "To maintain strict scope control and ensure on-time delivery within the 6-week schedule, the following activities are explicitly excluded from this Statement of Work unless added via a mutually executed Project Change Request (PCR):"),
            ("BULLETS", [
                "No Statutory or Regulatory Auditing: Google Cloud PSO does not perform formal statutory, regulatory, PCI-DSS QSA, ISO 27001, SOC 2, or financial audits. All deliverables represent consultative engineering assessments and posture verifications.",
                "Zero Plaintext Data or Private Key Access: The Agentic PQC Readiness Engine inspects GCP control-plane configuration metadata only. Google Cloud PSO will never access, decrypt, export, or inspect Customer plaintext payloads, database records, or raw cryptographic key material.",
                "No Direct Production Cutover or Production Code Modification by PSO: Google Cloud PSO provides prescriptive 5-step CLI/Terraform runbooks, refactoring blueprints, and guided validation in a designated non-production project during Week 5. Execution of changes in production environments remains the sole responsibility of Customer under Customer's Change Advisory Board (CAB) governance.",
                "No Source Code Decompilation of Third-Party Commercial Off-The-Shelf (COTS) Binaries: Application cryptographic agility assessments cover Customer-owned workloads, configurations, and documented API integrations, excluding reverse engineering of proprietary third-party binaries.",
            ]),
            ("H2", "7. Customer Responsibilities, SLA Prerequisites & Governance Cadence"),
            ("NUMBERED", [
                "IAM & Environment Onboarding (SLA — Within 3 Business Days of Kickoff): Customer will provision the four read-only GCP IAM roles (roles/cloudasset.viewer, roles/cloudkms.viewer, roles/privateca.auditor, roles/compute.viewer) at the in-scope Organization level (organizations/<CUSTOMER_ORG_ID>) as specified in PQC_User_and_Consultant_Guide. Delays in IAM provisioning beyond Day 3 may result in a day-for-day extension of the 6-week schedule.",
                "Stakeholder Workshop Participation: Customer will ensure timely attendance of Cloud Security Architects, KMS/PKI Owners, Network/SRE Leads, Identity Architects, and Application Leads during the Week 1 Calibration Workshops and Weeks 4–5 Architecture & Refactoring Workshops.",
                "Non-Production Pilot Sandbox (By End of Week 3): Customer will designate one non-production GCP project with Cloud KMS API enabled to host the guided Week 5 Cloud HSM PQC key creation and dual-stack verification lab.",
                "Weekly Steering Cadence & Deliverable Acceptance Window (5 Business Days): Google Cloud PSO and Customer Project Managers will conduct a 30-minute Weekly Status & Risk Sync every Friday. Upon submission of each formal deliverable (D-01 through D-06), Customer will review and provide written acceptance or consolidated feedback within five (5) business days, after which the deliverable is deemed accepted.",
            ]),
            ("H2", "8. Statement of Work Execution & Authorized Sign-Off Block"),
            ("P", "By signing below, the authorized representatives of Customer (<CUSTOMER_LEGAL_NAME>) and Google Cloud Consulting (PSO) agree to the scope, 6-week schedule, deliverables, assumptions, and governance terms set forth in this Statement of Work:"),
            ("TABLE", [
                ["Signatory Party", "Authorized Representative Name & Title", "Signature", "Execution Date"],
                ["Customer (<CUSTOMER_LEGAL_NAME>)", "[ Leave Blank — Populate Name & Title ]", "____________________________________", "[ YYYY-MM-DD ]"],
                ["Google Cloud Consulting (PSO)", "[ Leave Blank — Populate Name & Title ]", "____________________________________", "[ YYYY-MM-DD ]"],
            ]),
        ],
    },
    # -------------------------------------------------------------------------
    # 02. Technical Design Document (TDD) — DEEP L400 TEMPLATE-DRIVEN SPEC
    # -------------------------------------------------------------------------
    {
        "doc_name": "PQC_Technical_Design_Document_TDD",
        "old_names": ["02_PQC_Technical_Design_Document_TDD.md", "02_PQC_Technical_Design_Document_TDD"],
        "cover_title": "Post-Quantum Cryptography\u000bTechnical Design Doc (TDD)",
        "cover_subtitle": "Google Cloud Consulting (PSO) — Low-Level Engineering, Quantum Physics & ADK Tool Specification",
        "page2_headline": "Technical Design Document (TDD): Agentic PQC Readiness & CBOM Engine",
        "page2_subtitle": "L400 Software Architecture, 4-Vector Telemetry Introspection, Quantum Circuit Equations & Self-Calibrating Memory",
        "exec_summary": (
            "This L400 Technical Design Document (TDD) specifies the low-level software engineering, mathematical "
            "equations, API introspection schemas, and self-calibrating memory structures of the Agentic PQC Readiness "
            "& CBOM Engine. Designed as a reusable Google Cloud Consulting (PSO) technical blueprint, it connects the "
            "macro topology in PQC_System_Architecture_Specification, the stakeholder calibration parameters from "
            "PQC_Discovery_Questionnaire, and the deployment workflows in PQC_User_and_Consultant_Guide."
        ),
        "blocks": [
            ("H2", "1. Engineering Context, Breaking Changes & Deployment Configuration Template"),
            ("P", "Migrating enterprise cloud infrastructure to Post-Quantum Cryptography (PQC) under NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NIST IR 8547 (Final, Oct 2026), White House EO 14412, and NSA CNSA 2.0 is not a drop-in key rotation. It introduces fundamental mathematical, wire-format, and API breaking changes that require deterministic automated analysis:"),
            ("BULLETS", [
                "Harvest Now, Decrypt Later (HNDL) & Store Now, Decrypt Later (SNDL): Adversaries intercept encrypted TLS sessions, database backups, and archival ciphertexts today to decrypt them retroactively once Cryptographically Relevant Quantum Computers (CRQCs) reach the ~2,330 to ~4,098 logical qubit threshold required by Shor's algorithm.",
                "Wire-Format & Artifact Size Expansion (20x to 51x Bloat): Classical ECDSA P-256 signatures occupy 64 bytes (and RSA-2048 occupies 256 bytes), whereas NIST FIPS 204 ML-DSA-65 signatures require 3,309 bytes (~4.4 KB in Base64URL JWTs) and public keys require 1,952 bytes. This breaks reverse proxies, NGINX/Envoy ingresses, Apigee API Gateways, and browser cookies configured with 4KB/8KB HTTP header limits, as well as fixed-width database columns (e.g., VARBINARY(256)).",
                "Cryptographic API Contract Shift (Decrypt -> KEM Encapsulate/Decapsulate): Post-quantum key establishment (ML-KEM / X-Wing) eliminates direct asymmetric decryption (AsymmetricDecrypt). Applications must be refactored to execute client-side Key Encapsulation (Encapsulate) paired with Cloud KMS Decapsulate() and RFC 9180 Hybrid Public Key Encryption (HPKE) or Google Tink SDK envelope encryption.",
                "Digital Signature Pre-Hashing Shift (Digest -> Raw Data / External-Mu): Classical Cloud KMS AsymmetricSign accepts pre-computed SHA-256/384 digests, whereas ML-DSA (FIPS 204) requires signing the raw message payload (data field) or computing a 64-byte external-mu hash over the public key TR and message.",
            ]),
            ("H3", "1.1 Customer Deployment Configuration Manifest (Template Specification)"),
            ("P", "When deploying the agent in a contracted customer environment or PSO project (following PQC_User_and_Consultant_Guide), populate the environment identifiers below. Fields are intentionally left blank in this master template so each engagement records its isolated runtime endpoints:"),
            ("TABLE", [
                ["Configuration Parameter", "Environment Variable / Config Key", "Expected Format / URI Pattern", "Customer Environment Value (Populate at Deployment)"],
                ["Target GCP Organization Scope", "PQC_TARGET_ORG_ID", "organizations/<CUSTOMER_ORG_ID>", "[ Leave Blank — Populate in Customer Environment ]"],
                ["Agent Host GCP Project ID", "GOOGLE_CLOUD_PROJECT", "<CUSTOMER_HOST_PROJECT_ID>", "[ Leave Blank — Populate in Customer Environment ]"],
                ["Vertex AI Agent Engine URI", "VERTEX_AI_REASONING_ENGINE_URI", "projects/<PROJECT_NUMBER>/locations/<REGION>/reasoningEngines/<ENGINE_ID>", "[ Leave Blank — Populate in Customer Environment ]"],
                ["Cloud Run Interactive Web UI URL", "CLOUD_RUN_SERVICE_URL", "https://<SERVICE_NAME>-<PROJECT_NUMBER>.<REGION>.run.app", "[ Leave Blank — Populate in Customer Environment ]"],
                ["Scanner Service Account Identity", "SCANNER_SERVICE_ACCOUNT", "<SA_NAME>@<HOST_PROJECT_ID>.iam.gserviceaccount.com", "[ Leave Blank — Populate in Customer Environment ]"],
                ["Calibration & CBOM Storage Path", "PQC_CALIBRATION_STORE_PATH", "gs://<CUSTOMER_BUCKET>/calibration_history.jsonl", "[ Leave Blank — Populate in Customer Environment ]"],
            ]),
            ("H2", "2. Low-Level Software Package Architecture & ADK Tool Contracts"),
            ("P", "The codebase is organized into a modular neuro-symbolic Python architecture where the Google ADK LlmAgent (pqc_agent/agent.py) delegates 100% of telemetry introspection, quantum circuit math, financial simulation, and historical calibration to 12 deterministic Python tools across 5 specialized modules:"),
            ("TABLE", [
                ["Module File", "Registered ADK Tool Function", "Input Arguments", "Deterministic Output Contract"],
                ["pqc_agent/agent.py", "create_pqc_agent / root_agent", "model_name, GenerateContentConfig (temp=0.1, thinking=MEDIUM)", "Orchestrates 12 tools; enforces zero-hallucination scorecard rules and 6-part PSO report structure."],
                ["tools/gcp_inventory.py", "scan_organization_pqc_readiness", "organization_id: str", "Parallel 16-worker org scan returning validated_executive_scorecard, 4-vector blast-radius, and per-key playbooks."],
                ["tools/gcp_inventory.py", "scan_pqc_readiness", "project_id: str", "Single-project KMS/HSM inventory, CMEK bindings, and deterministic maturity metrics."],
                ["tools/gcp_inventory.py", "discover_all_crypto_assets", "scope: str", "Full enumeration of KMS keys, Certificate Authority Service (CAS) CAs, and workload bindings."],
                ["tools/gcp_inventory.py", "generate_pqc_migration_plan", "scope: str", "Phased 30-60-90 day migration plan, 5-step Cloud HSM runbooks, and symmetric 90-day rotation commands."],
                ["tools/gcp_inventory.py", "generate_application_pqc_refactoring_guide", "scope: str", "Side-by-side Python/Go SDK code diffs (AsymmetricDecrypt -> KEM Decapsulate + HPKE) and Envoy/NGINX configs."],
                ["tools/gcp_inventory.py", "export_cyclonedx_cbom", "scope: str", "OWASP CycloneDX v1.6 JSON CBOM with NIST OIDs, cryptoProperties, and quantum readiness statuses."],
                ["tools/pqc_detectors.py", "scan_ssl_policies", "scope: str", "Audits Compute Engine SslPolicies for TLS 1.3 + RESTRICTED profile (X25519MLKEM768 hybrid KEM readiness)."],
                ["tools/pqc_detectors.py", "scan_import_jobs_pqc", "scope: str", "Audits Cloud KMS ImportJobs for classical RSA-OAEP wrapping vs. quantum-safe HPKE X-Wing transport."],
                ["tools/quantum_engine.py", "run_quantum_cryptanalysis_simulation", "scope: str", "Computes Gidney-Ekera/Roetteler qubits, Core-SVP bits, fall-order ranking, and 10k Monte Carlo Q-VaR (95%)."],
                ["tools/calibration_engine.py", "calibrate_assessment_context", "scope, industry_sector, X, Y, Z, gateway_header_limit_kb, notes", "Persists stakeholder discovery overrides into calibration_history.jsonl and recalculates Mosca margins."],
                ["tools/calibration_engine.py", "get_historical_calibration_profile", "scope: str", "Loads cumulative learned calibration parameters and sector multipliers before assessment execution."],
                ["tools/report_exporter.py", "export_pqc_assessment_reports", "scope: str, output_dir: str", "Exports Executive Board Report (.md/.html), Engineering Playbook (.md/.html), and CycloneDX v1.6 CBOM (.json)."],
            ]),
            ("H2", "3. Deep Specification of the 4-Layer Telemetry & 4-Vector Blast-Radius Engine"),
            ("H3", "3.1 Intelligent Runtime Scope Resolution & Tenant Sandbox Interception (_resolve_scope)"),
            ("P", "When executed inside managed Vertex AI Agent Engine containers, the runtime environment injects internal Google-managed tenant project identifiers (matching project-*-tp). The _resolve_scope(raw_scope) function intercepts these ephemeral identifiers, validates whether a customer Organization ID or Project ID was explicitly supplied, and automatically resolves active child projects via Cloud Resource Manager API v3 (projects.search) with concurrent worker pooling."),
            ("H3", "3.2 Layer 1 — Cloud KMS, Cloud HSM & Cloud EKM Control-Plane Introspection"),
            ("BULLETS", [
                "API Traversal Pattern: Iterates concurrently across projects/*/locations/*/keyRings/*/cryptoKeys and inspects primaryVersion and enabled CryptoKeyVersions via cloudkms.googleapis.com/v1.",
                "Extracted Metadata Attributes: Captures purpose (ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ASYMMETRIC_DECRYPT, MAC, KEY_ENCAPSULATION), protectionLevel (SOFTWARE, HSM, EXTERNAL, EXTERNAL_VPC), algorithm (e.g., RSA_SIGN_PSS_2048_SHA256, EC_SIGN_P256_SHA256, GOOGLE_SYMMETRIC_ENCRYPTION, PQ_SIGN_ML_DSA_65, KEM_XWING), rotationPeriod, and nextRotationTime.",
                "Zero-Key-Material Guarantee: The scanner never invokes AsymmetricDecrypt, AsymmetricSign, Decapsulate, or Secret Manager accessSecretVersion. Only control-plane configuration descriptors are read.",
            ]),
            ("H3", "3.3 Layer 2 — The 4-Vector Application Blast-Radius Correlation Algorithm"),
            ("P", "To determine which applications break when a classical KMS key is migrated to PQC, tools/gcp_inventory.py executes a 4-Vector correlation graph across Cloud Asset Inventory (cloudasset.googleapis.com/v1):"),
            ("NUMBERED", [
                "Vector 1 — Direct CMEK Resource Binding (searchAllResources kmsKeyName): Identifies all BigQuery datasets/tables, Cloud Storage buckets, GKE clusters (etcd encryption), Compute Engine persistent disks, Cloud SQL instances, Spanner databases, and Pub/Sub topics encrypted via Customer-Managed Encryption Keys. Since CMEK uses AES-256-GCM under the hood, these workloads are flagged as COMPATIBLE_ZERO_REFACTORING_CMEK (requiring only <= 90-day key rotation hygiene).",
                "Vector 2 — Full-Text Workload Configuration Correlation: Queries CAI resource metadata, Cloud Run service environment variables, GKE ConfigMaps/Ingress annotations, and API Gateway descriptors referencing the KMS key URI.",
                "Vector 3 — IAM Policy Principal & Service Account Graph (searchAllIamPolicies): Traces every workload Service Account bound to roles/cloudkms.cryptoKeyEncrypterDecrypter, roles/cloudkms.signerVerifier, or roles/cloudkms.cryptoOperator on the target key, mapping the key directly to the microservice identity invoking it.",
                "Vector 4 — Project-Adjacent & PKI Certificate Authority Mapping: Correlates Certificate Authority Service (privateca.googleapis.com/v1) CA pools and subordinate CAs backed by Cloud KMS/HSM keys to downstream mTLS and ingress consumers.",
            ]),
            ("H3", "3.4 Layer 3 & 4 — Network Edge SslPolicy (X25519MLKEM768) & BYOK ImportJob Detectors"),
            ("BULLETS", [
                "Network Edge TLS 1.3 Hybrid PQC Detector (scan_ssl_policies): Queries compute.sslPolicies.list and regionSslPolicies.list. Policies with minTlsVersion < TLS_1_3 or permissive profiles (COMPATIBLE / MODERN) are flagged as VULNERABLE_TO_SNDL_ATTACKS because they permit classical ECDHE/RSA handshakes without hybrid post-quantum key exchange. Policies enforcing TLS_1_3 with RESTRICTED profile negotiate IETF hybrid X25519MLKEM768.",
                "BYOK Key Supply-Chain Detector (scan_import_jobs_pqc): Queries projects.locations.keyRings.importJobs.list. ImportJobs using RSA_OAEP_3072_SHA256 or RSA_OAEP_4096_SHA256 wrapping are flagged as VULNERABLE_KEY_IMPORT_TRANSPORT, prescribing migration to HPKE_KEM_XWING / ML-KEM wrapping.",
            ]),
            ("H2", "4. Mathematical Specification of the Quantum Physics & Stochastic Q-VaR Engine"),
            ("P", "The quantum simulation engine (tools/quantum_engine.py) avoids arbitrary qualitative risk labels by implementing peer-reviewed surface-code quantum circuit equations assuming superconducting planar surface codes at physical gate error rate p = 10^-3 (aligned with Google Quantum AI Willow error-correction scaling):"),
            ("TABLE", [
                ["Cryptographic Primitive", "Quantum Attack Circuit & Reference", "Logical Qubits (Q_L)", "Surface Code Distance (d) & Physical Qubits (Q_P)", "CRQC Runtime / Core-SVP Security Verdict"],
                ["ECDSA P-256 / Ed25519", "Shor ECDLP Windowed Point Addition (Roetteler et al., 2017)", "2,330 Logical Qubits", "d = 27 | ~13.4 Million Physical Qubits", "~9.5 Hours | RANK 1 — FALLS FIRST ON EARLY FTQC"],
                ["ECDSA P-384", "Shor ECDLP 384-Bit Modular Arithmetic (Roetteler / Haner 2020)", "3,484 Logical Qubits", "d = 29 | ~18.2 Million Physical Qubits", "~26.0 Hours | RANK 2 — FALLS BEFORE RSA-2048"],
                ["RSA-2048", "Shor Windowed Modular Exponentiation (Gidney & Ekera, 2021)", "4,098 Logical Qubits (2n+2)", "d = 27 | ~20.0 Million Physical Qubits", "~8.0 Hours | RANK 3 — CRITICAL HNDL TARGET"],
                ["RSA-3072 / RSA-4096", "Shor Lattice Surgery Factorization (Gidney & Ekera, 2021)", "6,146 to 8,194 Logical Qubits", "d = 29-31 | ~34.5M to 52.0M Physical Qubits", "21.5h - 49.0h | RANK 4-5 — HIGH HNDL TARGET"],
                ["KEM_XWING / ML-KEM-768", "Quantum BKZ Lattice Sieving (Albrecht Core-SVP / FIPS 203)", "Infeasible (Module-LWE dim=768)", "N/A — > 2^167 Quantum Gate Operations", "167-Bit Post-Quantum Core-SVP (QUANTUM-SAFE)"],
                ["PQ_SIGN_ML_DSA_65", "Quantum BKZ Lattice Sieving (Module-SIS / FIPS 204 Level 3)", "Infeasible (Module-SIS)", "N/A — > 2^166 Quantum Gate Operations", "166-Bit Post-Quantum Core-SVP (QUANTUM-SAFE)"],
                ["AES-256-GCM / HMAC-SHA256", "Grover Amplitude Amplification (Grassl et al. / NIST MAXDEPTH)", "2,953 Logical Qubits", "Requires 1.51e43 Serial Toffoli Gates (> 2^96 MAXDEPTH)", "128-Bit Effective PQ Security (QUANTUM-SAFE)"],
            ]),
            ("H3", "4.1 Counter-Intuitive Proof: Why ECDSA P-256 & P-384 Fall Before RSA-2048"),
            ("P", "Classical security intuition assumes ECDSA P-256 (128-bit classical security) is stronger than RSA-2048 (112-bit classical security). However, under Shor's algorithm on a fault-tolerant quantum computer, the required number of logical qubits scales linearly with key bit-length n: Q_logical(RSA) = 2n + 2 = 4,098 for n=2048 (Gidney & Ekera, 2021), whereas Q_logical(ECDLP) = 9n + 2*ceil(log2(n)) + 10 = 2,330 for n=256 (Roetteler et al., 2017). Because a quantum computer reaches 2,330 logical qubits years before it reaches 4,098 logical qubits, ECDSA P-256 and P-384 keys are always prioritized as Rank 1 and Rank 2 in the agent's remediation fall-order table."),
            ("H3", "4.2 10,000-Iteration Monte Carlo CRQC & Financial Q-VaR (95%) Formulation"),
            ("NUMBERED", [
                "Stochastic CRQC Arrival Distribution (Z_sim): Samples 10,000 trajectories of fault-tolerant logical qubit scaling from a log-normal distribution calibrated to published hardware roadmaps (mean Z = 8.5 years, adjustable via tools/calibration_engine.py).",
                "Mosca Inequality Evaluation per Iteration (X + Y > Z_sim): For each vulnerable asset i with confidentiality shelf-life X_i and refactoring lead time Y_i (calibrated via PQC_Discovery_Questionnaire), evaluates whether X_i + Y_i > Z_sim (HNDL breach for decryption/TLS assets) or Y_i > Z_sim (active forgery breach for signing/PKI assets).",
                "95th-Percentile Quantum Value-at-Risk (Q-VaR 95%): Aggregates simulated breach losses across all 10,000 runs (weighted by sector multiplier and per-record regulatory penalty) and extracts the 95th percentile in USD (unmitigated vs. residual post-PQC adoption).",
            ]),
            ("H2", "5. Adaptive Self-Calibration & Historical Learning Engine Design (tools/calibration_engine.py)"),
            ("P", "To ensure the agent adapts dynamically to each customer's industry vertical, regulatory regime, and architectural nuances without manual code edits, tools/calibration_engine.py implements a persistent closed-loop calibration architecture:"),
            ("BULLETS", [
                "Longitudinal Calibration Ledger (calibration_history.jsonl): Every execution of calibrate_assessment_context() appends a timestamped JSON record containing scope, industry_sector, mosca_parameters (X, Y, Z, safety margin Z - (X+Y)), gateway_header_limit_kb, qvar_sector_multiplier, compensating_controls_note, and project_tier_overrides.",
                "Pre-Configured Industry Vertical Profiles: Built-in mathematical baselines for BFSI_BANKING (X=15y, Y=3y, mult=1.35x), HEALTHCARE_GENOMICS (X=35y, Y=5y, mult=1.50x), PUBLIC_SECTOR_DEFENSE (X=30y, Y=4y, Z=7.5y, mult=1.60x), TELECOM_5G_CLOUD (X=10y, Y=3y, mult=1.25x), and ENERGY_OT_INDUSTRIAL (X=12y, Y=7y, mult=1.30x).",
                "Automatic Pre-Scan Context Injection: Before executing scan_organization_pqc_readiness or run_quantum_cryptanalysis_simulation, the agent calls get_historical_calibration_profile(scope), retrieving the latest learned parameters and historical audit trail so responses automatically self-calibrate across turns and sessions.",
            ]),
            ("H2", "6. Deterministic Scorecard Equations, CycloneDX v1.6 Schema & Refactoring Blueprints"),
            ("H3", "6.1 Separation of Asymmetric and Symmetric Denominators (Zero-Hallucination Guardrail)"),
            ("P", "To prevent LLMs from conflating symmetric AES-256 keys with asymmetric RSA/ECC keys, _compute_metrics_for_keys() pre-computes 7 locked KPIs in validated_executive_scorecard: (1) Asymmetric PQC Migration Score = Approved_PQC_Asymmetric_Keys / Total_Active_Asymmetric_Keys; (2) Symmetric Grover Resilience Score = AES256_And_SHA256_Keys / Total_Active_Symmetric_Keys; (3) Symmetric Rotation Hygiene Score = Symmetric_Keys_With_Rotation_<=90d / Total_Active_Symmetric_Keys; (4) Application PQC Compatibility Score; (5) Network TLS 1.3 Hybrid Readiness Score; (6) BYOK Import Transport Score; and (7) Weighted Overall PQC Maturity Index."),
            ("H3", "6.2 Application SDK & Gateway Refactoring Specifications"),
            ("TABLE", [
                ["Breaking Change Vector", "Legacy Classical Pattern", "Target Post-Quantum Pattern (Google Cloud)", "Required Infrastructure / Schema Pre-Requisite"],
                ["Asymmetric Encryption / Wrapping", "Cloud KMS AsymmetricDecrypt(ciphertext) with RSA_DECRYPT_OAEP_2048_SHA256 (256B ciphertext)", "Client-side KEM Encapsulate() + Cloud KMS Decapsulate() with KEM_XWING (1,120B ciphertext) or Google Tink HPKE", "Widen database ciphertext columns from VARBINARY(256) to VARBINARY(2048) before key cutover."],
                ["Digital Signatures & JWT Tokens", "Cloud KMS AsymmetricSign(digest) with EC_SIGN_P256_SHA256 (64B signature)", "Cloud KMS AsymmetricSign(data) with PQ_SIGN_ML_DSA_65 (3,309B signature / ~4.4KB Base64URL JWT)", "Increase Envoy max_request_headers_kb and NGINX large_client_header_buffers to 16KB-32KB."],
                ["External Ingress TLS Handshake", "Compute SslPolicy TLS_1_0 / TLS_1_2 MODERN profile (ECDHE-RSA)", "Compute SslPolicy minTlsVersion=TLS_1_3 + profile=RESTRICTED (X25519MLKEM768 hybrid KEM)", "Verify middlebox/firewall DPI MTU handling for 1,120B hybrid key-share ClientHello frames."],
                ["Preventive Governance Guardrails", "Unrestricted KMS algorithm creation across GCP projects", "Custom Org Policies: custom.pqcEnforceQuantumSafeKmsAlgorithms & custom.pqcEnforceSymmetricKeyRotation90d", "Deploy via gcloud org-policies set-policy at Folder/Org scope after canary validation."],
            ]),
        ],
    },
    # -------------------------------------------------------------------------
    # 03. Agentic PQC Security Recommendations Book — DEEP SECURITY & ARCHITECTURE GUIDE
    # -------------------------------------------------------------------------
    {
        "doc_name": "Agentic PQC Security Recommendations Book",
        "old_names": ["03_PQC_CISO_Recommendations_Book.md", "03_PQC_CISO_Recommendations_Book", "PQC_CISO_Recommendations_Book"],
        "cover_title": "Agentic PQC Readiness\u000bSecurity Recommendations",
        "cover_subtitle": "Google Cloud Consulting (PSO) — Enterprise Security Risk Quantification, Target Architecture & PQC Roadmap",
        "page2_headline": "Agentic PQC Security Recommendations Book: Posture, Q-VaR & Roadmap",
        "page2_subtitle": "Validated 7-KPI Security Scorecard, Surface-Code Quantum Fall-Order, Monte Carlo Q-VaR (95%) & 5-Pillar Google Cloud Security BOM",
        "exec_summary": (
            "This Agentic PQC Security Recommendations Book translates live Google Cloud control-plane telemetry and "
            "7-domain stakeholder calibration from the Agentic PQC Readiness & CBOM Engine into an actionable security "
            "leadership blueprint. Designed as a reusable customer engagement deliverable, it unifies deterministic "
            "7-KPI posture scoring, physical surface-code quantum cryptanalysis (explaining why 256-bit Elliptic Curve "
            "cryptography falls before RSA-2048), 10,000-iteration Monte Carlo Quantum Value-at-Risk (Q-VaR 95%) "
            "financial modeling, a 5-pillar Google Cloud Security Architecture Bill of Materials (BOM), and a phased "
            "2026–2035 migration roadmap aligned with NIST FIPS 203/204/205, NIST IR 8547, and EO 14412."
        ),
        "blocks": [
            ("H2", "1. Security Executive Context & Customer Environment Parameterization"),
            ("P", "Adversaries are actively executing Harvest-Now, Decrypt-Later (HNDL) and Store-Now, Decrypt-Later (SNDL) collection against encrypted enterprise traffic, database backups, and identity tokens today. Once Cryptographically Relevant Quantum Computers (CRQCs) reach the ~2,330 to ~4,098 logical qubit threshold required by Shor's algorithm, classical asymmetric primitives (RSA, Diffie-Hellman, ECDH, ECDSA, Ed25519) will be retroactively compromised. This Security Recommendations Book establishes the customer's verified cryptographic baseline and target Google Cloud security architecture."),
            ("P", "Consultative Security Advisory Framing (Non-Audit Positioning): Google Cloud Consulting (PSO) provides this document as a Consultative Post-Quantum Security Readiness Assessment, Posture Verification, and Target Architecture Blueprint. It does not constitute a statutory, regulatory, or compliance audit."),
            ("TABLE", [
                ["Security Engagement Parameter", "Template Configuration Token", "Expected Format / Target Scope", "Customer Environment Value (Populate per Engagement)"],
                ["Customer Legal Entity Name", "<CUSTOMER-LEGAL-NAME>", "Full legal name of the organization", "[ Leave Blank — Populate in Customer Environment ]"],
                ["Primary Regulated Industry Sector", "<INDUSTRY-SECTOR>", "BFSI | Healthcare & Genomics | Public Sector & Defense | Telecom & 5G | Energy & OT", "[ Leave Blank — Populate in Customer Environment ]"],
                ["Assessed GCP Organization Scope", "<CUSTOMER-ORG-ID>", "organizations/<12-DIGIT-ORG-ID>", "[ Leave Blank — Populate in Customer Environment ]"],
                ["Agentic PQC Host Project & Engine", "<CUSTOMER-HOST-PROJECT>", "Cloud Run / Vertex AI Agent Engine Host Project", "[ Leave Blank — Populate in Customer Environment ]"],
                ["Calibrated Mosca Horizons (X, Y, Z)", "<MOSCA-HORIZONS>", "Shelf-Life X (yrs) + Migration Y (yrs) vs. CRQC Z (yrs)", "[ Leave Blank — Populate from Discovery Questionnaire ]"],
                ["Security Leadership Sponsor", "<SECURITY-SPONSOR>", "VP of Information Security / Head of Cloud Security / GRC Lead", "[ Leave Blank — Populate in Customer Environment ]"],
            ]),
            ("H2", "2. Validated 7-KPI Organization Cryptographic Security Scorecard"),
            ("P", "Every execution of the Agentic PQC Readiness Engine computes seven deterministic Key Performance Indicators (KPIs) directly in Python across the customer's live GCP telemetry (Cloud KMS/HSM, Cloud Asset Inventory 4-Vector workload dependencies, Compute SSL/TLS policies, Certificate Authority Service, and BYOK ImportJobs). The table below presents the reference benchmark scorecard alongside target security SLAs:"),
            ("TABLE", [
                ["Security Control Domain (NIST FIPS 203/204/205 & IR 8547)", "Benchmark Score", "Target Security SLA", "Security Posture Verdict & Primary Exposure Vector"],
                ["1. Weighted Overall Agentic PQC Security Maturity", "70.0%", "100.0%", "MODERATE — Immediate remediation required on asymmetric signing & KEM keys."],
                ["2. Asymmetric Cryptography (Shor Immunity: RSA/ECC -> PQC)", "50.0%", "100.0%", "CRITICAL — Classical ECDSA P-256 and RSA-2048 keys exposed to Shor & HNDL."],
                ["3. Symmetric Data-at-Rest (AES-256 Grover Resilience)", "100.0%", "100.0%", "COMPLIANT — AES-256-GCM provides 128-bit effective post-quantum security."],
                ["4. Symmetric Key Rotation Hygiene (<= 90-Day Cryptoperiod)", "66.7%", "100.0%", "ACTION REQUIRED — Unrotated symmetric CMEKs increase ciphertext exposure volume."],
                ["5. Network Edge TLS 1.3 (X25519MLKEM768 Hybrid Readiness)", "50.0%", "100.0%", "MODERATE — Legacy TLS 1.0/1.2 SSL policies allow classical SNDL session capture."],
                ["6. BYOK / HYOK Supply Chain (Cloud KMS ImportJob Wrapping)", "50.0%", "100.0%", "MODERATE — Classical RSA-OAEP wrapping exposes imported key material in transit."],
                ["7. Application & API Gateway Crypto Agility (Tink & 16KB+ JWT)", "45.0%", "100.0%", "HIGH PRIORITY — Direct AsymmetricDecrypt calls and 8KB proxy header ceilings."],
            ]),
            ("H2", "3. Physical Quantum Fall-Order Prioritization (Why Elliptic Curves Fall Before RSA-2048)"),
            ("P", "A widespread misconception in enterprise security teams is that 256-bit Elliptic Curve Cryptography (ECDSA P-256, ECDH X25519, Ed25519) is more resistant to quantum computers than RSA-2048 because ECC is stronger against classical computers. In quantum physics, the exact opposite is true: Shor's algorithm solves the Elliptic Curve Discrete Logarithm Problem (ECDLP) with nearly half the logical qubits required to factor a 2048-bit RSA modulus."),
            ("BULLETS", [
                "Elliptic Curve Discrete Logarithm Vulnerability (Roetteler et al., 2017): Breaking a 256-bit elliptic curve (ECDSA P-256 / Ed25519 / X25519) requires Q_logical = 9n + 2*ceil(log2(n)) + 10 = 2,330 logical qubits and ~1.26 x 10^11 Toffoli gates. Under a planar surface code at code distance d = 27 (physical gate error rate 10^-3), this translates to ~3.40M to ~13.4M physical qubits (depending on magic-state distillation factory concurrency) and an ~8-to-9.5 hour runtime. Therefore, ECDSA P-256 and X25519 will be broken by smaller, earlier quantum processors than RSA-2048.",
                "Integer Factorization Vulnerability (Gidney & Ekera, 2021): Factoring an n = 2048-bit RSA modulus via windowed modular exponentiation requires Q_logical = 2n + 2 = 4,098 logical qubits and ~2.7 x 10^10 Toffoli gates (~5.97M to ~20.0M physical qubits at surface-code distance d = 27, executing in ~8.0 hours). While RSA-2048 requires ~1.76x more logical qubits than ECDSA P-256, it remains critically exposed to Harvest-Now, Decrypt-Later (HNDL) archival decryption.",
                "Module-Lattice & Symmetric Quantum Resilience (Albrecht Core-SVP & Grassl Grover): NIST FIPS 203 (ML-KEM-768 / KEM-XWING) and FIPS 204 (ML-DSA-65) rely on Module-LWE / Module-SIS lattices with BKZ block sizes beta >= 590–625, requiring > 2^156 to 2^167 quantum sieve operations. Symmetric AES-256-GCM under Grover's quadratic speedup (Grassl et al., 2016) requires ~2,953 logical qubits executing ~2^128 sequential oracle iterations—physically infeasible within cosmological timescales.",
            ]),
            ("TABLE", [
                ["Quantum Fall Order", "Cryptographic Primitive Class", "Logical Qubits (Shor / Grover)", "Physical Qubits (Surface Code d=27-31)", "Security Remediation Priority & Target Replacement"],
                ["1st to Fall (Earliest CRQC Break)", "ECDSA P-256 / Ed25519 / ECDH P-256", "2,330 Logical Qubits", "~3.40M – 13.4M Physical Qubits", "P0 Immediate — Migrate to Cloud HSM PQ-SIGN-ML-DSA-65 (FIPS 204) & X25519MLKEM768"],
                ["2nd to Fall (Critical HNDL Exposure)", "RSA-2048 (OAEP Decrypt / PSS Sign)", "4,098 Logical Qubits", "~5.97M – 20.0M Physical Qubits", "P1 Urgent — Migrate to Cloud HSM KEM-XWING / ML-KEM-768 (FIPS 203) & Google Tink SDK"],
                ["3rd to Fall (High HNDL Exposure)", "RSA-3072 / RSA-4096 (BYOK & Root PKI)", "6,146 – 8,194 Logical Qubits", "~15.0M – 52.0M Physical Qubits", "P2 Planned — Migrate CAS Root/Subordinate CAs & KMS ImportJobs to ML-DSA / SLH-DSA"],
                ["Quantum-Safe Target Baseline", "AES-256-GCM / ML-KEM-768 / ML-DSA-65", "Core-SVP >= 166b / Grover > 2^128", "Computationally Infeasible", "Target State — Enforce <= 90-day symmetric rotation & FIPS 140-3 Level 3 Cloud HSM"],
            ]),
            ("H2", "4. Financial Risk Quantification: Mosca's Theorem (X + Y > Z) & Monte Carlo Q-VaR (95%)"),
            ("P", "To enable Security Leadership, Risk Committees, and CFOs to prioritize capital allocation, the Agentic PQC Readiness Engine pairs Dr. Michele Mosca's inequality (X + Y > Z) with a 10,000-iteration Monte Carlo Quantum Value-at-Risk (Q-VaR 95%) simulation in USD:"),
            ("BULLETS", [
                "Mosca's Theorem (X + Y > Z) Operationalized: When the required confidentiality shelf-life of regulated data (X years) plus the engineering time required to refactor and migrate cryptographic infrastructure (Y years) exceeds the time remaining until a Cryptographically Relevant Quantum Computer arrives (Z years), the organization is in active HNDL breach status today.",
                "Benchmark Financial Exposure (Unmitigated vs. Mitigated Q-VaR 95%): Across the reference enterprise benchmark, unmitigated 95th-percentile Quantum Value-at-Risk reaches US$ 10.32 Million (driven by regulatory fines under GDPR/LGPD/HIPAA/PCI-DSS, per-record notification costs, and sovereign IP loss). Completing the recommended Google Cloud PQC architecture migration reduces residual Q-VaR (95%) to US$ 0.15 Million—a 98.5% net financial risk reduction.",
            ]),
            ("TABLE", [
                ["Regulated Industry Vertical", "Confidentiality Horizon (X) & Migration Time (Y)", "Mosca Sum (X + Y) vs. CRQC Window (Z=9 yrs)", "Q-VaR Sector Multiplier", "Primary Financial & Regulatory Exposure Drivers"],
                ["Banking & Financial Services (BFSI)", "X = 15 yrs | Y = 3.5 yrs", "18.5 yrs > 9 yrs (OVERDUE: -9.5 yrs)", "1.35x Multiplier", "ISO 20022 wire settlement, PCI-DSS v4.0.1, EU DORA, BACEN BCB 85/4893, long-term credit archives."],
                ["Healthcare, Biopharma & Genomics", "X = 35 yrs | Y = 5.0 yrs", "40.0 yrs > 9 yrs (OVERDUE: -31.0 yrs)", "1.50x Multiplier", "Non-revocable human genomic sequences, permanent EHR/PHI records, HIPAA, FDA SaMD cybersecurity."],
                ["Public Sector, Defense & National Infra", "X = 30 yrs | Y = 4.5 yrs", "34.5 yrs > 9 yrs (OVERDUE: -25.5 yrs)", "1.60x Multiplier", "Sovereign citizen registries, classified CUI, White House EO 14412, OMB M-26-15, NSA CNSA 2.0."],
                ["Telecommunications, 5G Core & Cloud", "X = 12 yrs | Y = 3.0 yrs", "15.0 yrs > 9 yrs (OVERDUE: -6.0 yrs)", "1.30x Multiplier", "3GPP SA3 5G SUCI subscriber identity privacy, eSIM root PKI, carrier IPsec/MACsec trunks."],
                ["Energy, Utilities & Industrial OT", "X = 20 yrs | Y = 6.0 yrs", "26.0 yrs > 9 yrs (OVERDUE: -17.0 yrs)", "1.40x Multiplier", "Substation SCADA/PLC long-lived firmware roots, NERC CIP, IEC 62443 critical infrastructure."],
            ]),
            ("H2", "5. Recommended Target Security Architecture on Google Cloud (5-Pillar Product BOM)"),
            ("P", "To remediate discovered vulnerabilities without disrupting production SLAs, Google Cloud PSO recommends a defense-in-depth Target Security Architecture built on five native Google Cloud security capabilities:"),
            ("TABLE", [
                ["Pillar #", "Google Cloud Security Product Pillar", "Target PQC Primitives & Capabilities", "Identified Cryptographic Gap Resolved & Business Value"],
                ["Pillar 1", "Cloud HSM (FIPS 140-3 Level 3) & Cloud KMS PQC", "PQ-SIGN-ML-DSA-65 (FIPS 204), KEM-XWING & ML-KEM-768 (FIPS 203), SLH-DSA (FIPS 205), HPKE BYOK Import.", "Eliminates Shor vulnerability on asymmetric signing/encryption keys and secures BYOK key import chains inside hardware roots of trust."],
                ["Pillar 2", "Global External Application Load Balancing (L7), Cloud Armor & CAS", "Hybrid TLS 1.3 Key Exchange (X25519MLKEM768) + Dual-Root CAS PKI (ML-DSA-65 / SLH-DSA).", "Neutralizes passive Store-Now, Decrypt-Later (SNDL) packet capture at the internet edge and modernizes internal mTLS PKI."],
                ["Pillar 3", "Google Tink SDK & Apigee / Envoy Gateway Modernization", "Hybrid Envelope Encryption (KEM-XWING KEK + AES-256-GCM DEK) + 16KB–32KB HTTP Header Buffers.", "Abstracts KEM Encapsulate/Decapsulate API breaking changes from application code and prevents HTTP 431 errors on 3,309B ML-DSA JWTs."],
                ["Pillar 4", "VPC Service Controls (VPC-SC) & Private Service Connect (PSC)", "Context-aware zero-trust service perimeters around BigQuery, Cloud Storage, Cloud SQL & Cloud KMS.", "Prevents bulk Harvest-Now, Decrypt-Later (HNDL) ciphertext exfiltration even if an application credential is compromised."],
                ["Pillar 5", "Binary Authorization, Artifact Registry & SCC Enterprise", "Post-quantum container attestation (PQ-SIGN-ML-DSA-65) + continuous cryptographic drift monitoring.", "Secures the CI/CD software supply chain against forged signatures and enforces continuous compliance with NIST IR 8547."],
            ]),
            ("H2", "6. Domain-by-Domain Prescriptive Security Recommendations (Domains 1 to 7)"),
            ("BULLETS", [
                "Domain 1 (Governance & CycloneDX v1.6 CBOM): Establish a formal Post-Quantum Migration Office chartered by Security Leadership; integrate automated OWASP CycloneDX v1.6 CBOM generation into quarterly GRC reviews and mandate PQC readiness attestations in third-party vendor procurement contracts.",
                "Domain 2 (Data Confidentiality Shelf-Life & HNDL Containment): Immediately enclose all Tier-0 data repositories with confidentiality shelf-life X >= 10 years (BigQuery datasets, GCS archival buckets, Cloud SQL instances) inside VPC Service Controls (VPC-SC) perimeters and re-wrap archival DEKs under hybrid KEM-XWING KEKs.",
                "Domain 3 (KMS, Cloud HSM & BYOK Supply Chain): Upgrade all production asymmetric keys from SOFTWARE protection level to FIPS 140-3 Level 3 Cloud HSM; enforce automated <= 90-day rotation (7,776,000s) on all AES-256 symmetric CMEKs; and replace classical RSA-OAEP BYOK ImportJobs with quantum-safe HPKE wrapping.",
                "Domain 4 (Application Cryptographic Agility & Database Schemas): Refactor direct Cloud KMS AsymmetricDecrypt() API calls to Google Tink SDK envelope encryption; audit relational/NoSQL database schemas (Cloud SQL, Spanner, AlloyDB) to expand fixed-width signature/key columns (e.g., VARBINARY(256) -> BLOB / BYTEA) before cutover.",
                "Domain 5 (Identity, OIDC/SAML & API Gateway Buffers): Increase HTTP request header limits (max-request-headers-kb) from 4KB/8KB to 16KB–32KB across Envoy proxies, NGINX ingresses, and Apigee API Gateways to accommodate 3,309-byte ML-DSA-65 signatures (~4.4 KB Base64URL JWTs), or adopt opaque Phantom Tokens at the edge.",
                "Domain 6 (Edge TLS 1.3 X25519MLKEM768 & CAS PKI): Enforce minTlsVersion = TLS-1-3 and the RESTRICTED cipher profile across all Google Cloud HTTPS Load Balancers; tune TCP initial congestion windows (initcwnd) for 1,120-byte hybrid key shares; and deploy parallel cross-signed ML-DSA-65 subordinate CAs in Certificate Authority Service (CAS).",
                "Domain 7 (CI/CD Supply Chain & Binary Authorization): Migrate container image and CI/CD artifact signing attestors in Binary Authorization from ECDSA P-256 / RSA-PSS to Cloud HSM PQ-SIGN-ML-DSA-65, and adopt stateless hash-based SLH-DSA (FIPS 205) for long-lived firmware roots.",
            ]),
            ("H2", "7. Preventive Governance: Declarative GCP Organization Policy Guardrails"),
            ("P", "Remediation without preventive governance leads to cryptographic regression as engineering teams provision new cloud resources. Google Cloud PSO recommends enforcing three declarative GCP Organization Policy guardrails upon completing Phase 3 pilot validation:"),
            ("NUMBERED", [
                "Enforce Hardware Root of Trust (constraints/cloudkms.allowedProtectionLevels): Configure the Organization Policy constraint on production folders to permit only HSM and EXTERNAL protection levels, blocking creation of software-backed asymmetric keys.",
                "Block New Classical Asymmetric Key Provisioning (Custom Org Policy Constraint): Deploy a Custom Organization Policy constraint on googleapis.com/CryptoKey resources evaluating resource.versionTemplate.algorithm to deny creation of new RSA-SIGN-*, RSA-DECRYPT-*, and EC-SIGN-* algorithms in migrated production projects without an approved exception label.",
                "Enforce Minimum TLS 1.3 & Restricted Cipher Profiles (Custom Compute SSL Policy Constraint): Enforce custom constraints on compute.googleapis.com/SslPolicy resources requiring minTlsVersion == TLS-1-3 and profile == RESTRICTED across all external load balancers.",
            ]),
            ("H2", "8. Phased Multi-Horizon Security Modernization Roadmap (2026–2035)"),
            ("P", "The table below sequences the recommended security engineering workstreams across three operational horizons—from the initial 6-week PSO assessment through full classical algorithm disallowance under NIST IR 8547 and EO 14412:"),
            ("TABLE", [
                ["Migration Horizon & Timeline", "Strategic Security Objective", "Core Engineering & Governance Deliverables", "Target Maturity & Q-VaR Reduction"],
                ["Horizon 1: Days 1–45\n(6-Week PSO Assessment & Pilot)", "Baseline Discovery, Calibration, Edge Containment & Non-Prod HSM Pilot", "Complete 7-Domain Discovery Questionnaire, CycloneDX v1.6 CBOM, Q-VaR (95%) model, VPC-SC HNDL containment, and Week 5 Non-Prod Cloud HSM PQC Key Pilot.", "Maturity: 45% -> 70%\nQ-VaR Reduction: -35% (Containment)"],
                ["Horizon 2: Months 3–12\n(Hybrid Dual-Stack Production Rollout)", "Production Edge TLS 1.3 (X25519MLKEM768), Tink SDK KEM & Dual-Key JWKS", "Upgrade L7 Load Balancers to TLS 1.3 X25519MLKEM768; tune Envoy/Apigee to 16KB–32KB; refactor Tier-0 apps to Google Tink KEM-XWING; rotate P0 ECDSA/RSA keys in Cloud HSM.", "Maturity: 70% -> 92%\nQ-VaR Reduction: -90% (Tier-0 PQC)"],
                ["Horizon 3: Months 12–36+\n(Full NIST IR 8547 2030/2035 Compliance)", "Full Classical Asymmetric Deprecation, PQC Root PKI & Preventive Org Policies", "Complete CAS ML-DSA-65 / SLH-DSA PKI cutover; enforce preventive GCP Organization Policies blocking RSA/ECC; disable all legacy classical key versions ahead of 2030 mandate.", "Maturity: 92% -> 100%\nQ-VaR Reduction: -98.5% (Quantum-Safe)"],
            ]),
        ],
    },
    # -------------------------------------------------------------------------
    # 04. Kickoff Engagement Deck (Doc Guide)
    # -------------------------------------------------------------------------
    {
        "doc_name": "PQC_Kickoff_Engagement_Deck",
        "old_names": ["04_PQC_Kickoff_Engagement_Deck.md", "04_PQC_Kickoff_Engagement_Deck"],
        "cover_title": "Post-Quantum Cryptography\u000bKickoff Engagement Guide",
        "cover_subtitle": "Google Cloud Consulting (PSO) — Executive Kickoff Agenda & Speaker Narrative",
        "page2_headline": "Engagement Kickoff & Executive Presentation Guide: PQC Readiness",
        "page2_subtitle": "Structured Workshop Agenda, Speaker Talking Points & Day-1 Readiness Checklist",
        "exec_summary": (
            "This document provides the structured slide-by-slide narrative, executive talking points, and workshop "
            "agenda for kicking off a Google Cloud Consulting (PSO) Post-Quantum Cryptography (PQC) Readiness Assessment."
        ),
        "blocks": [
            ("H2", "1. Kickoff Meeting Agenda & Stakeholder Alignment"),
            ("BULLETS", [
                "1. Executive Context (15 min): Harvest Now, Decrypt Later (HNDL), Mosca's Inequality (X + Y > Z), and NIST FIPS 203/204/205, NIST IR 8547 (Final), and EO 14412 regulatory timelines.",
                "2. Autonomous Agentic Discovery Demo (15 min): Live walkthrough of the 7-second Organization-wide scan across Cloud KMS, Cloud Asset Inventory, TLS/SSL policies, and BYOK ImportJobs.",
                "3. Quantum Physics & Financial Q-VaR Modeling (15 min): Understanding why ECDSA P-256 falls before RSA-2048 and reviewing Monte Carlo Q-VaR (95%) financial exposure.",
                "4. Consultative Execution Plan & Next Steps (15 min): Reviewing the 7-domain PQC_Discovery_Questionnaire, IAM prerequisites, and workshop schedule.",
            ]),
            ("H2", "2. Slide-by-Slide Executive Narrative"),
            ("TABLE", [
                ["Slide #", "Slide Title", "Key Executive Message & Proof Points"],
                ["Slide 1", "Securing the Post-Quantum Future on Google Cloud", "Autonomous PQC Discovery, Quantum Cryptanalysis & NIST FIPS 203/204/205 Migration powered by Google ADK & Gemini 3.1 Pro."],
                ["Slide 2", "The Urgency: HNDL & Mosca's Theorem (X + Y > Z)", "Adversaries harvest encrypted traffic today. For 10-year regulated data, the HNDL breach window is already open."],
                ["Slide 3", "Why PQC Migration Breaks Legacy Applications", "ML-DSA-65 signatures are 3,309 bytes (51x larger than ECDSA) and ML-KEM replaces Encrypt/Decrypt with Encapsulate/Decapsulate."],
                ["Slide 4", "4-Layer Organization-Wide Discovery in 7 Seconds", "Scans Cloud KMS/HSM, 4-Vector CAI workload bindings, Compute SslPolicies (X25519MLKEM768), and KMS ImportJobs."],
                ["Slide 5", "Deterministic Quantum Physics & Monte Carlo Q-VaR", "Gidney & Ekera (2021) + Roetteler ECDLP qubit modeling + 10,000-run Monte Carlo Q-VaR (US$ 10.32M -> US$ 0.15M)."],
                ["Slide 6", "Consultative 5-Step Per-Key HSM Runbooks", "Copy-pasteable gcloud HSM commands, IAM bindings, Google Tink refactoring, and post-change verification."],
            ]),
            ("H2", "3. Day-1 Readiness Checklist"),
            ("NUMBERED", [
                "Confirm Target GCP Scope: Validate Customer Organization ID (organizations/<CUSTOMER_ORG_ID>) or priority production folder hierarchy.",
                "Verify Read-Only Service Account Permissions: Confirm roles/cloudasset.viewer, roles/cloudkms.viewer, roles/privateca.auditor, and roles/compute.viewer as documented in PQC_User_and_Consultant_Guide.",
                "Complete Sector & Domain Calibration: Conduct the stakeholder discovery interview using PQC_Discovery_Questionnaire to calibrate confidentiality shelf-life (X) and migration lead time (Y).",
            ]),
        ],
    },
    # -------------------------------------------------------------------------
    # 05. Delivery Model & Sizing Guide
    # -------------------------------------------------------------------------
    {
        "doc_name": "PQC_Delivery_Model_and_Sizing_Guide",
        "old_names": ["05_PQC_Delivery_Model_and_Sizing_Guide.md", "05_PQC_Delivery_Model_and_Sizing_Guide"],
        "cover_title": "Post-Quantum Cryptography\u000bDelivery & Sizing Guide",
        "cover_subtitle": "Google Cloud Consulting (PSO) — 4-Stage Methodology, RACI & T-Shirt Sizing",
        "page2_headline": "PSO Delivery Model & T-Shirt Sizing Guide: Agentic PQC Accelerator",
        "page2_subtitle": "Standardized Execution Workflow, Staffing Tiers & Margin Optimization for PSO, TAM & GSD",
        "exec_summary": (
            "This Delivery Model & Sizing Guide defines the standardized Google Cloud Consulting (PSO / TAM / GSD) "
            "execution workflow, RACI matrix, and T-Shirt sizing tiers for delivering Post-Quantum Cryptography (PQC) "
            "assessments at high margin using the Agentic PQC Readiness & CBOM Engine."
        ),
        "blocks": [
            ("H2", "1. End-to-End 4-Stage Delivery Flow"),
            ("NUMBERED", [
                "Stage 1 — Automated Setup & 7-Domain Scope Calibration (Day 1): Configure read-only IAM permissions (PQC_User_and_Consultant_Guide) and execute PQC_Discovery_Questionnaire to calibrate industry data shelf-life (X), migration velocity (Y), and CRQC horizon (Z).",
                "Stage 2 — Automated 4-Vector Telemetry Scan, CBOM & Quantum Risk Modeling (Weeks 2–3): Execute parallel discovery across Cloud KMS, CAI 4-Vector workload bindings, Compute SSL Policies, Certificate Authority Service, and BYOK ImportJobs, generating the OWASP CycloneDX v1.6 CBOM and Monte Carlo Q-VaR (95%) model.",
                "Stage 3 — Edge TLS 1.3 Architecture, Tink SDK Crypto Agility & Non-Prod HSM Pilot (Weeks 4–5): Design hybrid post-quantum TLS 1.3 (X25519MLKEM768) and CAS PQC PKI hierarchies, conduct application refactoring workshops (Google Tink SDK & 16KB–32KB JWT buffers), and execute the guided 5-step Cloud HSM PQC cutover pilot.",
                "Stage 4 — Preventive GCP Org Policy Guardrails, Security Recommendations Book & Closeout (Week 6): Deliver preventive GCP Organization Policy YAML constraints blocking legacy RSA/ECC creation, finalize the Agentic PQC Security Recommendations Book and 2026–2035 Migration Roadmap, and conduct the Executive Board Closeout.",
            ]),
            ("H2", "2. Engagement T-Shirt Sizing Matrix (Small / Medium / Large)"),
            ("TABLE", [
                ["Sizing Tier", "Customer Footprint", "Manual Effort (Legacy)", "Agent-Accelerated Effort", "Recommended PSO Staffing"],
                ["Small (Fast-Track / Single Domain)", "1-15 GCP Projects | <50 KMS Keys", "6–8 Weeks (240–320 Hours)", "2–3 Weeks (88–120 Hours)", "1 PSO Security Consultant + 1 Security CE (Part-Time)"],
                ["Medium (Standard Enterprise — Baseline SOW)", "15-100 GCP Projects | 50-300 KMS Keys", "12–16 Weeks (480–640 Hours)", "6 Weeks (224 Hours: 100h PSO Consultant, 80h Security CE, 44h GSD Architect)", "1 PSO Security Consultant (100h) + 1 Security CE (80h) + 1 GSD Architect (44h)"],
                ["Large (Global / Multi-Org Regulated)", "100-1,000+ GCP Projects | 300+ Keys & PKI", "20–24 Weeks (800–960 Hours)", "8–10 Weeks (320–400 Hours)", "2 PSO Security Consultants + 1 Security CE + 1 GSD Lead Architect"],
            ]),
            ("H2", "3. RACI Governance Matrix"),
            ("TABLE", [
                ["Workstream / Activity", "Google PSO Architect", "Google TAM / CE", "Customer CISO / GRC", "Customer AppSec / SRE"],
                ["Read-Only IAM & Scope Onboarding", "Consulted (C)", "Informed (I)", "Approver (A)", "Responsible (R)"],
                ["7-Domain Discovery & Self-Calibration", "Responsible (R)", "Consulted (C)", "Consulted (C)", "Consulted (C)"],
                ["Agentic PQC Scan & CycloneDX v1.6 CBOM", "Responsible (R)", "Consulted (C)", "Informed (I)", "Consulted (C)"],
                ["Monte Carlo Q-VaR & Executive Board Readout", "Responsible (R)", "Accountable (A)", "Approver (A)", "Informed (I)"],
                ["5-Step HSM Key Cutover & Tink Refactoring", "Consulted (C)", "Informed (I)", "Informed (I)", "Responsible (R)"],
            ]),
        ],
    },
    # -------------------------------------------------------------------------
    # 06. Elevator Pitch & Lab Prompts Catalog
    # -------------------------------------------------------------------------
    {
        "doc_name": "PQC_Elevator_Pitch_and_Lab_Prompts",
        "old_names": ["06_PQC_Elevator_Pitch_and_Lab_Prompts.md", "06_PQC_Elevator_Pitch_and_Lab_Prompts"],
        "cover_title": "Post-Quantum Cryptography\u000bElevator Pitch & Prompts",
        "cover_subtitle": "Google Cloud Consulting (PSO) — Field Enablement Battlecard & Live Demo Catalog",
        "page2_headline": "Executive Elevator Pitch, Battlecard & Lab Prompts Catalog",
        "page2_subtitle": "60-Second C-Level Narrative, Objection Handling & Copy-Paste Prompts for Gemini Enterprise",
        "exec_summary": (
            "A field-ready enablement guide for CALs, Portfolio Leads, TAMs, and PSO Architects containing the "
            "60-second C-Level elevator pitch, objection-handling battlecard, and copy-paste prompt catalog for live "
            "customer demonstrations in Gemini Enterprise and Cloud Run ADK Web UI."
        ),
        "blocks": [
            ("H2", "1. 60-Second Executive Elevator Pitch (Board & CISO View)"),
            ("P", "Why This Matters Now: Adversaries are actively executing Harvest Now, Decrypt Later (HNDL) interception on encrypted enterprise traffic and backups today, knowing that Cryptographically Relevant Quantum Computers (CRQCs) will break classical RSA and ECC keys via Shor's algorithm. Meanwhile, NIST FIPS 203/204/205, NIST IR 8547 (Final), Executive Order 14412, and NSA CNSA 2.0 mandate deprecation of classical asymmetric cryptography by 2030."),
            ("P", "The Google Cloud Advantage: Instead of spending 4 to 8 weeks building manual spreadsheet inventories, Google Cloud's Agentic PQC Readiness & CBOM Engine scans your entire GCP Organization in under 7 seconds, calibrates risk to your specific industry vertical, maps every KMS key, certificate, TLS policy, and live application dependency, quantifies financial exposure in dollars via a 10,000-iteration Monte Carlo Q-VaR simulation, exports an official OWASP CycloneDX v1.6 CBOM, and generates copy-pasteable 5-step Cloud HSM migration runbooks."),
            ("H2", "2. Field Sales & Technical Battlecard"),
            ("TABLE", [
                ["Customer Objection / Question", "Winning Consultative Response & Technical Proof"],
                ["\"Quantum computers are still years away — why start now?\"", "Mosca's Theorem (X + Y > Z): If your data must remain confidential for 10-35 years (X) and enterprise migration takes 2-5 years (Y), any CRQC arrival within X+Y years means traffic intercepted today via HNDL is already compromised."],
                ["\"Can't we just rotate our RSA keys to PQC keys overnight?\"", "No — ML-DSA-65 signatures are 3,309 bytes (51x larger than ECDSA P-256), which breaks API Gateways with 4KB/8KB HTTP header limits, and ML-KEM uses Encapsulate/Decapsulate instead of Encrypt/Decrypt. Our agent detects and refactors these dependencies."],
                ["\"Does this scanner require agents or access to our secret data?\"", "Zero agents and zero plaintext access. It uses 100% read-only GCP control-plane APIs (Cloud KMS, Cloud Asset Inventory, Compute SSL, CAS) and completes in ~6.7 seconds."],
            ]),
            ("H2", "3. Copy-Paste Lab & Demo Prompts Catalog"),
            ("BULLETS", [
                "Prompt 1 (Full Consultative Assessment & 5-Step Migration Guide): Run a complete Consultative PQC Readiness Assessment and Step-by-Step Migration Guide across organizations/<CUSTOMER_ORG_ID>, including the Validated Executive Scorecard, 10,000-run Monte Carlo Q-VaR (95%), Physical Quantum Fall-Order Ranking, and 5-Step Remediation Runbooks for 100% of vulnerable keys.",
                "Prompt 2 (Executive CISO Board Briefing & Q-VaR): Run an Executive Board Post-Quantum Cryptography (PQC) Assessment for organizations/<CUSTOMER_ORG_ID>, highlighting the validated executive scorecard, Monte Carlo Q-VaR (95%) in USD, regulatory alignment (NIST IR 8547 Final & EO 14412), and Google Cloud Security Product BOM.",
                "Prompt 3 (Application Refactoring & Org Policy Guardrails): Generate the Google Tink SDK Python envelope encryption refactoring guide, Envoy Hybrid PQC TLS 1.3 (X25519MLKEM768) configuration, and preventive GCP Organization Policy YAML guardrails.",
            ]),
        ],
    },
    # -------------------------------------------------------------------------
    # 07. Discovery Questionnaire — DEEP 7-DOMAIN & SECTOR-CALIBRATED SPEC
    # -------------------------------------------------------------------------
    {
        "doc_name": "PQC_Discovery_Questionnaire",
        "old_names": ["07_PQC_Discovery_Questionnaire.md", "07_PQC_Discovery_Questionnaire"],
        "cover_title": "Post-Quantum Cryptography\u000bDiscovery Questionnaire",
        "cover_subtitle": "Google Cloud Consulting (PSO) — 7-Domain Sector-Calibrated Posture Verification & Discovery Guide",
        "page2_headline": "PQC Deep Technical Discovery & Sector Calibration Questionnaire",
        "page2_subtitle": "Rigorous 7-Domain Consultative Discovery Instrument Calibrating Mosca's Theorem (X+Y>Z) & Agent Memory",
        "exec_summary": (
            "This deep technical discovery and calibration questionnaire is the foundational stakeholder assessment "
            "instrument for Google Cloud Consulting (PSO) Post-Quantum Cryptography (PQC) engagements. While the "
            "Agentic PQC Readiness & CBOM Engine automatically discovers 100% of GCP control-plane cryptographic "
            "metadata, this calibrated 7-domain instrument captures industry-specific regulatory requirements, "
            "off-cloud HSM/PKI topologies, application breaking-change constraints, and exact Mosca parameters "
            "(X, Y, Z) that directly feed the agent's self-calibrating memory engine (tools/calibration_engine.py)."
        ),
        "blocks": [
            ("H2", "1. Questionnaire Overview, Consultative Rigor & Architectural Integration"),
            ("P", "An automated cloud control-plane scan reveals what cryptographic algorithms are deployed (e.g., RSA-2048, ECDSA P-256, AES-256-GCM), but cannot by itself know the statutory confidentiality lifespan of the underlying business data, the contractual constraints of third-party SaaS peers, or the firmware replacement cycle of on-premises hardware. This questionnaire bridges that gap with rigorous, evidence-backed posture verification depth."),
            ("H3", "1.1 Consultative Readiness Assessment vs. Statutory Certification Boundary"),
            ("P", "Important Engagement Framing: Google Cloud Consulting (PSO) conducts a Consultative PQC Readiness Assessment, Cryptographic Inventory (CBOM), and Posture Verification—never a formal statutory or regulatory certification. However, to ensure the customer's engineering and executive teams are fully prepared for external regulatory scrutiny, every domain in this questionnaire is structured with verification-grade rigor, concrete evidence artifacts, and direct control traceability aligned with NIST FIPS 203/204/205, NIST IR 8547 (Final, Oct 2026), White House EO 14412, OMB M-26-15, NSA CNSA 2.0, UK NCSC (2028/2031/2035), EU DORA, and PCI-DSS v4.0."),
            ("H3", "1.2 How This Questionnaire Connects to the Technical & Executive Suite"),
            ("NUMBERED", [
                "Feeds the Self-Calibrating Memory Engine (PQC_User_and_Consultant_Guide): Consultant findings from Domains 1-7 are entered via structured Calibration Prompts into calibrate_assessment_context(), persisting in calibration_history.jsonl.",
                "Calibrates the Mathematical Risk Engine (PQC_Technical_Design_Document_TDD): Domain 2 defines X (Data Confidentiality Shelf-Life in years) and per-record breach severity; Domains 4-7 define Y (Engineering & Infrastructure Refactoring Duration in years); Domain 1 calibrates Z (CRQC Risk Appetite Horizon), driving Mosca's Inequality (X + Y > Z) and the 10,000-iteration Monte Carlo Q-VaR (95%) simulation.",
                "Governs Target Reference Architecture Selection (PQC_System_Architecture_Specification & PQC_CISO_Recommendations_Book): Answers regarding FIPS 140-3 Level 3 mandates, sovereign key control (BYOK/EKM), and VPC Service Controls directly determine the recommended 5-product Google Cloud Security BOM.",
            ]),
            ("H2", "2. Industry Sector Calibration Matrix (Vertical-Specific Threat & Compliance Profiles)"),
            ("P", "Post-Quantum Cryptography urgency varies dramatically across industry verticals. Before conducting domain interviews, the PSO Architect selects the customer's primary sector profile to establish baseline Mosca (X, Y, Z) parameters and regulatory weights:"),
            ("TABLE", [
                ["Industry Vertical & Profile Key", "Confidentiality Horizon (X) & Migration Time (Y)", "Primary HNDL & Cryptographic Exposure Vectors", "Applicable Regulatory & Standards Mandates", "Default Q-VaR Multiplier & Protocol Bottlenecks"],
                [
                    "Banking, Financial Services & Capital Markets\n[BFSI_BANKING]",
                    "X = 10 to 25 Years\nY = 2.5 to 4.0 Years\n(X+Y = 12.5-29 yrs > Z)",
                    "Inter-bank mTLS settlement, ISO 20022 wire payloads, SWIFT/payment tokenization, long-term credit/mortgage archives, and high-frequency JWT/OAuth2 API gateways.",
                    "PCI-DSS v4.0 (Req 4.2.1), EU DORA (Art. 9), Central Bank (BACEN/Fed/ECB) Cyber Resilience, NIST IR 8547, FIPS 203/204.",
                    "1.35x Q-VaR Multiplier | High sensitivity to 3,309B ML-DSA-65 JWT header bloat on Apigee/Envoy and legacy on-prem PKCS#11 HSM wrapping."
                ],
                [
                    "Healthcare, Life Sciences, Biopharma & Genomics\n[HEALTHCARE_GENOMICS]",
                    "X = 30 to 50+ Years\nY = 4.0 to 8.0 Years\n(X+Y = 34-58 yrs >> Z)",
                    "Permanent Electronic Health Records (EHR/PHI), human genomic sequences (non-revocable biometric identity), pharmaceutical R&D IP, and connected medical devices (IoMT).",
                    "HIPAA Security Rule, FDA Premarket Medical Device Cybersecurity Guidance, GDPR/LGPD Genomic Protection, NIST FIPS 203/204/205.",
                    "1.50x Q-VaR Multiplier | Constrained IoMT/DICOM medical imaging firmware unable to parse 15KB-25KB PQC X.509 certificate chains without edge TLS proxy termination."
                ],
                [
                    "Public Sector, Defense, Intelligence & National Critical Infra\n[PUBLIC_SECTOR_DEFENSE]",
                    "X = 25 to 50 Years\nY = 3.0 to 6.0 Years\n(Strict Statutory Deadlines)",
                    "Sovereign citizen identity/tax registries, national Root PKI hierarchies, classified/CUI diplomatic and defense communications, and air-gapped key ceremonies.",
                    "White House EO 14412 (Dec 31, 2030 KEM / Dec 31, 2031 Sig), OMB M-26-15, NSA CNSA 2.0, NIST IR 8547 Final, UK NCSC 2028/2031/2035.",
                    "1.60x Q-VaR Multiplier | Mandatory FIPS 140-3 Level 3 Cloud HSM or Cloud EKM external key residency and FAR Sec. 6(c) supplier CBOM attestation."
                ],
                [
                    "Telecommunications, 5G Core, ISP & Cloud/SaaS Providers\n[TELECOM_5G_CLOUD]",
                    "X = 7 to 15 Years\nY = 2.0 to 4.0 Years\n(High-Throughput Edge)",
                    "3GPP 5G core control-plane interconnects, SIM/eSIM provisioning roots, carrier IPsec/MACsec backbone trunks, and multi-million RPS multi-tenant edge TLS termination.",
                    "3GPP SA3 Post-Quantum 5G Security, IETF Hybrid TLS 1.3 (X25519MLKEM768), ETSI Quantum-Safe Cryptography, NIST FIPS 203/204.",
                    "1.25x Q-VaR Multiplier | Extreme sensitivity to TCP initial congestion window (initcwnd) packet fragmentation under 1,120B ML-KEM key shares."
                ],
                [
                    "Energy, Utilities, Industrial OT (SCADA/ICS), Automotive & Retail\n[ENERGY_OT_INDUSTRIAL]",
                    "X = 10 to 20 Years\nY = 5.0 to 12.0 Years\n(Hardware Lifecycle Bound)",
                    "Substation SCADA/ICS controllers, smart-grid meters, connected vehicle V2X ECUs, long-lived OTA firmware signing chains, and high-volume retail POS payment terminals.",
                    "NERC CIP, IEC 62443, ISO/SAE 21434 (Automotive), NIST FIPS 205 (SLH-DSA for stateless firmware signing), PCI-DSS v4.0.",
                    "1.30x Q-VaR Multiplier | Physical field hardware cannot be easily replaced; requires stateless hash-based SLH-DSA/ML-DSA firmware roots and hybrid OT gateways."
                ],
            ]),
            ("H2", "3. Comprehensive 7-Domain Technical Discovery & Calibration Matrix"),
            ("P", "The questionnaire is structured across 7 weighted technical domains. The table below maps each domain to its target stakeholders, calibration weight, extracted mathematical variables, and required verification evidence:"),
            ("TABLE", [
                ["Domain # & Weight", "Technical Discovery Domain", "Target Customer Stakeholders", "Extracted Calibration Variables", "Required Verification Evidence Artifacts"],
                ["Domain 1 (15%)", "Strategic Governance, CBOM Maturity & Regulatory Posture", "CISO, Chief Risk Officer, GRC Lead, Legal Counsel", "Z_appetite, Regulatory Deadlines, Supplier FAR Scope", "PQC Charter, Executive Sponsor Mandate, Existing CBOM/SBOM, Vendor Contracts"],
                ["Domain 2 (20%)", "Data Confidentiality Shelf-Life (X) & HNDL Exposure", "Data Protection Officer (DPO), Enterprise Data Architects", "X_years (per data tier), Breach Cost/Record (USD), Transit Exposure", "Data Classification Policy, Retention Schedules, Backup/Archival Topology"],
                ["Domain 3 (15%)", "Key Management (KMS), HSMs & BYOK/HYOK Supply Chain", "Cloud Security Architects, Cryptography & KMS/HSM Leads", "HSM Tier (FIPS 140-3 L3), BYOK Wrapping Method, Rotation SLA", "Cloud KMS/HSM Inventory, On-Prem HSM Architecture (Thales/Entrust), ImportJob Logs"],
                ["Domain 4 (20%)", "Application Runtime, Cryptographic SDKs & API Contracts", "Principal AppSec Engineers, Lead Software Architects", "Y_app_refactor_years, SDK Compatibility Ratio, DB Schema Limits", "Codebase Dependency Manifests (OpenSSL/JCA/Tink), DB Column Schemas, KMS API Call Graphs"],
                ["Domain 5 (10%)", "Identity, Token Signing (JWT/OIDC) & Gateway Buffer Limits", "IAM Architecture Lead, API Platform / Apigee / Envoy Owners", "gateway_header_limit_kb, JWT Token Size Ceiling, Cookie Limits", "Envoy/NGINX/Apigee Configs, IdP (Okta/Cloud Identity/Keycloak) JWKS Specs"],
                ["Domain 6 (10%)", "Network Perimeter (TLS 1.3), Service Mesh (mTLS) & PKI (CAS)", "Network Security Architects, PKI/CA Administrators, SREs", "TLS 1.3 X25519MLKEM768 Readiness, CA Hierarchy Depth, MTU Drop Rate", "Compute SslPolicy Configs, CAS Root/Subordinate Cert Chains, Firewall/DPI Rules"],
                ["Domain 7 (10%)", "CI/CD Supply Chain Signing, Refactoring Velocity (Y) & Cutover", "DevSecOps Lead, Release Engineering, Platform SRE", "Y_infra_years, Canary Dual-Signing Capability, Org Policy Readiness", "Binary Authorization Policies, Cosign/Sigstore Workflows, Release Velocity Metrics"],
            ]),
            ("H3", "3.1 Domain 1 — Strategic Governance, CBOM Maturity & Regulatory Compliance Posture (Weight: 15%)"),
            ("NUMBERED", [
                "Q1.1 — Executive PQC Migration Lead & Governance Charter (EO 14412 / OMB M-26-15): Has the organization formally designated an enterprise Post-Quantum Cryptography Migration Lead and established a cross-functional governance charter spanning Security, Platform Engineering, Application Development, and Procurement? [Evidence: Governance Charter / RACI]",
                "Q1.2 — Automated Cryptographic Bill of Materials (OWASP CycloneDX v1.6 CBOM): Does the organization maintain an automated, machine-readable CBOM indexing all asymmetric and symmetric algorithms, OIDs, key lengths, protection levels, and consuming workloads, or is cryptographic tracking reliant on manual spreadsheets? [Evidence: Current CBOM/Inventory Sample]",
                "Q1.3 — Binding Regulatory & Statutory Deadlines: Which external mandates govern your cryptographic estate (e.g., White House EO 14412 Dec 31, 2030 Key Establishment & Dec 31, 2031 Digital Signatures; NIST IR 8547 Final 2030 Deprecation / 2035 Disallowance; UK NCSC 2028/2031/2035; NSA CNSA 2.0; EU DORA; PCI-DSS v4.0)? [Calibrates: Regulatory Target Year]",
                "Q1.4 — Third-Party SaaS, Vendor & Supply-Chain Cryptographic Governance (FAR Sec. 6(c) & NIST NCCoE): Do procurement contracts mandate that third-party software vendors, SaaS providers, and external API partners deliver CycloneDX v1.6 CBOM attestations and support hybrid PQC TLS 1.3 (X25519MLKEM768) prior to 2030? [Evidence: Third-Party Risk Questionnaire]",
                "Q1.5 — Preventive Cloud Governance Guardrails (GCP Organization Policies): Are preventive Organization Policy constraints enforced today to block developers from provisioning new classical RSA-2048/ECDSA keys or unrotated symmetric keys in production projects? [Evidence: Org Policy YAML]",
            ]),
            ("H3", "3.2 Domain 2 — Data Confidentiality Lifespan (X) & HNDL Interception Exposure (Weight: 20%)"),
            ("NUMBERED", [
                "Q2.1 — Maximum Statutory & Business Confidentiality Shelf-Life (Mosca Parameter X): Across your highest-sensitivity datasets (e.g., customer PII/PHI, genomic records, financial settlement ledgers, sovereign secrets, M&A/R&D intellectual property), what is the maximum number of years (X) the data must remain confidential after creation? [Calibrates: confidentiality_years_x]",
                "Q2.2 — Active Harvest Now, Decrypt Later (HNDL) Transit Exposure: Which encrypted data streams traverse public internet links, cross-border submarine cables, multi-tenant peering exchanges, or third-party partner interconnects where passive packet capture by state-sponsored adversaries is plausible today? [Calibrates: HNDL Exposure Surface]",
                "Q2.3 — Long-Term Archival, Cold Storage & Backup Retention Topology: How are multi-year database snapshots, regulatory compliance archives (Cloud Storage Coldline/Archive, BigQuery long-term tables, tape exports), and disaster-recovery backups encrypted, and are their Data Encryption Keys (DEKs) wrapped by classical RSA-OAEP Key Encryption Keys (KEKs)? [Evidence: Backup Encryption Spec]",
                "Q2.4 — Quantitative Financial Breach Impact & Record Valuation (Monte Carlo Q-VaR Calibration): What is the estimated financial, regulatory fine, and reputational cost per compromised record or per critical workload breach in USD to calibrate the 10,000-iteration Monte Carlo Quantum Value-at-Risk (Q-VaR 95%) model? [Calibrates: qvar_sector_multiplier]",
                "Q2.5 — Data Perimeter Isolation (VPC Service Controls): Are crown-jewel Cloud Storage buckets, BigQuery datasets, and Cloud KMS keyrings enclosed within Google Cloud VPC Service Controls (VPC-SC) perimeters with Private Service Connect (PSC) to prevent bulk ciphertext exfiltration? [Evidence: VPC-SC Perimeter Config]",
            ]),
            ("H3", "3.3 Domain 3 — Key Management Systems (KMS), HSMs & BYOK/HYOK Supply Chain (Weight: 15%)"),
            ("NUMBERED", [
                "Q3.1 — Hardware Root of Trust vs. Software Key Residency: What percentage of production asymmetric signing and decryption keys reside in FIPS 140-3 Level 3 Hardware Security Modules (Google Cloud HSM) versus software-backed Cloud KMS or application-memory keystores? [Evidence: KMS ProtectionLevel Breakdown]",
                "Q3.2 — On-Premises HSM Estate & BYOK Key Wrapping Transport (Cloud KMS ImportJobs): Does the organization generate keys in on-premises HSMs (e.g., Thales Luna, Entrust nShield, Securosys) and import them into Google Cloud KMS via ImportJobs? If so, are keys wrapped using classical RSA_OAEP_3072/4096 (vulnerable to Shor interception during import) or quantum-safe HPKE (KEM_XWING / ML-KEM)? [Evidence: ImportJob Configs]",
                "Q3.3 — External Key Manager (Cloud EKM) & Sovereign Hold-Your-Own-Key (HYOK) Latency: Are any workloads using Cloud EKM over the internet or VPC to external key appliances, and does the external appliance vendor support NIST FIPS 203/204 primitives without exceeding Cloud EKM SLA timeouts? [Evidence: EKM Architecture]",
                "Q3.4 — Symmetric CMEK Grover Resilience & <= 90-Day Rotation Hygiene: While AES-256-GCM CMEK keys are resilient against Grover's algorithm (128-bit effective post-quantum security), what percentage of symmetric keys enforce automated rotationPeriod <= 90 days (7,776,000s) to bound cryptoperiod exposure? [Evidence: KMS Rotation Audit]",
                "Q3.5 — Legacy Hash & MAC Deprecation (HMAC-SHA1 / Triple-DES): Are any legacy payment, EDI, or authentication workloads still utilizing HMAC-SHA1 (< 80-bit post-quantum collision resistance) or 112-bit 3DES keys requiring immediate replacement with HMAC-SHA256/512 or AES-256? [Evidence: KMS MAC Inventory]",
            ]),
            ("H3", "3.4 Domain 4 — Application Runtime, Cryptographic SDKs & API Breaking-Change Readiness (Weight: 20%)"),
            ("NUMBERED", [
                "Q4.1 — Direct Cloud KMS AsymmetricDecrypt() API Dependency (KEM Breaking Change): Which applications or microservices invoke the Cloud KMS asymmetricDecrypt() API directly with RSA_DECRYPT_OAEP keys? (Note: NIST FIPS 203 ML-KEM / KEM_XWING replaces direct decryption with client-side Encapsulate() + KMS Decapsulate() + RFC 9180 HPKE symmetric AEAD wrapping.) [Evidence: KMS API Caller Graph]",
                "Q4.2 — Direct Cloud KMS AsymmetricSign(digest) vs. Raw Message Signing (ML-DSA Breaking Change): Which applications pass pre-hashed SHA-256/384 digests into asymmetricSign(digest)? (Note: NIST FIPS 204 ML-DSA-65 requires passing the raw message payload in the data field or computing a 64-byte external-mu hash.) [Evidence: Signing SDK Code Inspection]",
                "Q4.3 — Cryptographic Abstraction Layer Adoption (Google Tink SDK): Do internal engineering teams write raw cryptographic primitives using low-level libraries (BouncyCastle, Java JCA, Python cryptography, Node crypto), or do they use high-level envelope encryption abstractions such as Google Tink SDK that abstract key encapsulation and hybrid transitions? [Calibrates: Y_app_refactor_years]",
                "Q4.4 — Database & Persistent Storage Column Byte-Width Constraints: Do relational or NoSQL databases (Cloud SQL, Spanner, AlloyDB, Bigtable) store ciphertexts, public keys, or digital signatures in fixed-width columns (e.g., VARCHAR(256), VARBINARY(512)) that will truncate or throw SQL overflow errors when storing 1,120-byte KEM_XWING ciphertexts or 3,309-byte ML-DSA-65 signatures? [Evidence: DDL Schema Review]",
                "Q4.5 — Language Runtime & TLS Library Version Floor: Which versions of OpenSSL, BoringSSL, Go, JDK, .NET, and Python run in production containers, and how many legacy runtimes lack native support for NIST FIPS 203/204 OIDs? [Evidence: Container SBOM]",
            ]),
            ("H3", "3.5 Domain 5 — Identity, Token Signing (JWT/OIDC/SAML) & Gateway Header Buffer Limits (Weight: 10%)"),
            ("NUMBERED", [
                "Q5.1 — OAuth2 / OIDC JWT & SAML Assertion Signing Primitives: Which Identity Providers (IdPs) or internal token-issuance microservices sign JSON Web Tokens (JWTs) or SAML assertions using RS256, ES256 (ECDSA P-256), or EdDSA (Ed25519)? [Evidence: JWKS Endpoint Inspection]",
                "Q5.2 — Reverse Proxy, Ingress & API Gateway HTTP Header Size Limits (3,309B ML-DSA-65 Impact): Replacing a 64-byte ES256 signature with a 3,309-byte ML-DSA-65 signature expands a Base64URL-encoded Authorization: Bearer <JWT> header by ~4.4 KB. What are the current maximum HTTP request header buffer settings across your Cloud Load Balancers, Apigee proxies, Envoy sidecars (max_request_headers_kb), and NGINX ingresses (large_client_header_buffers)? [Calibrates: gateway_header_limit_kb]",
                "Q5.3 — Browser Cookie & Mobile Client Storage Ceilings: Are signed JWTs stored inside browser HTTP cookies (which enforce a strict 4,096-byte RFC 6265 per-cookie ceiling across Chrome/Safari/Firefox) where a 4.4 KB ML-DSA-65 JWT will silently fail to set or be dropped by the browser? [Evidence: Session Management Architecture]",
                "Q5.4 — Dual-Key JWKS Publication & Canary Token Verification: Can your API gateways and relying-party microservices validate a JWKS endpoint publishing both classical (ES256/RS256) and post-quantum (ML-DSA-65) public keys simultaneously during a zero-downtime canary migration? [Evidence: IAM Canary Test Plan]",
            ]),
            ("H3", "3.6 Domain 6 — Network Perimeter (TLS 1.3), Service Mesh (mTLS), PKI Hierarchy & Interconnect (Weight: 10%)"),
            ("NUMBERED", [
                "Q6.1 — External Cloud Load Balancing SSL Policy Posture (SNDL Mitigation): What percentage of Google Cloud HTTPS/SSL Load Balancers enforce minTlsVersion = TLS_1_3 with the RESTRICTED profile (enabling IETF hybrid X25519MLKEM768 key exchange) versus legacy TLS_1_0 / TLS_1_2 profiles vulnerable to Store Now, Decrypt Later (SNDL) capture? [Evidence: scan_ssl_policies Output]",
                "Q6.2 — Internal PKI Hierarchy (Certificate Authority Service — CAS) & Chain Bloat: How many Root and Subordinate Certificate Authorities exist in Google Cloud CAS or on-premises Active Directory CS / EJBCA? Can internal mTLS clients handle full post-quantum X.509 certificate chains (Root + Intermediate + Leaf signed with ML-DSA-65/87), which expand TLS handshake certificate payloads from ~3 KB to ~15 KB–25 KB? [Evidence: PKI Hierarchy Diagram]",
                "Q6.3 — Stateful Firewall, IDS/IPS & DPI Middlebox Packet Drop Risk: Do on-premises or cloud network inspection appliances drop or reset TLS 1.3 ClientHello packets that exceed a single 1,500-byte Ethernet MTU frame (splitting across TCP segments due to the 1,120-byte X25519MLKEM768 hybrid key share)? [Evidence: Network Firewall Vendor Matrix]",
                "Q6.4 — Service Mesh East-West mTLS (Anthos Service Mesh / Istio / GKE): How is pod-to-pod mTLS configured in GKE clusters, and what is the rotation TTL of workload identity certificates (e.g., 24-hour SPIFFE/SPIRE certs vs. static multi-year certs)? [Evidence: Mesh SecurityConfig]",
                "Q6.5 — Hybrid Cloud VPN (HA VPN / IPsec IKEv2) & Dedicated Interconnect: Which Diffie-Hellman groups protect Phase-1/Phase-2 IKEv2 key exchanges on Cloud VPN tunnels, and is MACsec or Post-Quantum Pre-Shared Key (PPK, RFC 8784) enabled on hybrid interconnects carrying regulated traffic? [Evidence: VPN Tunnel Configs]",
            ]),
            ("H3", "3.7 Domain 7 — CI/CD Software Supply Chain Signing, Refactoring Velocity (Y) & Cutover Readiness (Weight: 10%)"),
            ("NUMBERED", [
                "Q7.1 — Container Image & Artifact Signing (Binary Authorization / Cosign): Are GKE and Cloud Run deployments gated by Google Cloud Binary Authorization attestors, and what asymmetric algorithm signs container digests and CI/CD provenance attestations today? [Evidence: Binary Authorization Policy]",
                "Q7.2 — Long-Lived Firmware, Mobile App & OTA Code-Signing Roots: Does the organization sign long-lived device firmware, OS kernels, or mobile binaries where the public verification key is burned into read-only hardware/ROM (requiring stateless hash-based NIST FIPS 205 SLH-DSA or dual-root signing)? [Evidence: Firmware Signing Architecture]",
                "Q7.3 — Historical Cryptographic Refactoring Velocity (Mosca Parameter Y Calibration): Based on past enterprise-wide security migrations (e.g., SHA-1 to SHA-256, TLS 1.0 to TLS 1.2, or Log4j remediation), how many years (Y) does your engineering organization require to refactor, test, and deploy cryptographic SDK updates across 100% of production applications? [Calibrates: migration_years_y]",
                "Q7.4 — Automated Crypto-Agility & Emergency Key-Compromise Runbooks: If a classical algorithm or CA were catastrophically broken tomorrow, can your CI/CD pipelines rotate keys and redeploy all consuming workloads within 72 hours without manual code changes? [Evidence: Crypto-Agility Runbook]",
            ]),
            ("H2", "4. Quantitative Maturity Scoring Rubric & Automated Calibration Parameter Mapping"),
            ("P", "During the Phase 1 workshop, the PSO Architect scores each of the 7 domains on a 1-to-5 verification rubric and maps the extracted parameters directly into the agent's calibrate_assessment_context() tool (detailed in PQC_User_and_Consultant_Guide):"),
            ("TABLE", [
                ["Maturity Level", "Posture Classification", "Verification Criteria & Evidence Threshold", "Calibrated Impact on Mosca (Y) & Q-VaR Simulation"],
                ["Level 1 (0-20%)", "Ad-Hoc / Cryptographically Blind", "No CBOM; hardcoded RSA/ECDSA in code; 4KB/8KB gateway headers; TLS 1.0/1.1 active; no HSM or 90d rotation.", "Increases Y by +2.0 years; maximum HNDL breach probability in Monte Carlo Q-VaR."],
                ["Level 2 (21-45%)", "Inventory Initiated / Classical Bound", "Partial KMS visibility; heavy direct AsymmetricDecrypt() usage; classical RSA-OAEP BYOK; no PQC pilot.", "Increases Y by +1.0 year; high refactoring effort required in Phase 3."],
                ["Level 3 (46-70%)", "Crypto-Agile Foundation", "Automated CycloneDX v1.6 CBOM active; AES-256 CMEK >=90d rotation; TLS 1.3 enabled on primary ingresses.", "Baseline Y maintained; moderate asymmetric refactoring scope."],
                ["Level 4 (71-90%)", "Hybrid PQC Operational", "Google Tink SDK envelope abstraction deployed; HTTP buffers >=16KB; Cloud HSM KEM_XWING & ML-DSA-65 in canary.", "Reduces Y by -0.75 years; >85% reduction in simulated Monte Carlo Q-VaR."],
                ["Level 5 (91-100%)", "Quantum-Safe & Self-Calibrating", "100% asymmetric keys on FIPS 203/204/205 in Cloud HSM; TLS 1.3 X25519MLKEM768 enforced; preventive Org Policies active.", "Mosca safety margin positive (X+Y < Z); residual Q-VaR reduced by >=98.5%."],
            ]),
        ],
    },
    # -------------------------------------------------------------------------
    # 08. System Architecture Specification — DEEP L300/L400 TEMPLATE SPEC
    # -------------------------------------------------------------------------
    {
        "doc_name": "PQC_System_Architecture_Specification",
        "old_names": ["08_PQC_System_Architecture_Specification.md", "08_PQC_System_Architecture_Specification"],
        "cover_title": "Post-Quantum Cryptography\u000bArchitecture Specification",
        "cover_subtitle": "Google Cloud Consulting (PSO) — Enterprise AI Agent Reference Architecture & Security Model",
        "page2_headline": "System Architecture Specification: Agentic PQC Readiness Engine",
        "page2_subtitle": "5-Plane Neuro-Symbolic AI Topology, Multi-Tenant Deployment Templates, Closed-Loop Self-Calibration & Zero-Trust Model",
        "exec_summary": (
            "This L300/L400 System Architecture Specification defines the enterprise reference architecture for the "
            "Agentic Post-Quantum Cryptography (PQC) Readiness & CBOM Engine. Designed as a modular, template-driven "
            "specification for deployment in any contracted customer Google Cloud environment, it details the 5-plane "
            "neuro-symbolic AI architecture (combining Gemini 3.1 Pro / 2.5 Pro cognitive orchestration on Google ADK "
            "with deterministic quantum physics, 4-vector Cloud Asset Inventory introspection, and closed-loop historical "
            "self-calibration), enterprise VPC-SC deployment patterns, and STRIDE zero-trust security boundaries."
        ),
        "blocks": [
            ("H2", "1. Architectural Vision, Design Tenets & Customer Environment Template Manifest"),
            ("P", "Analyzing an enterprise's Post-Quantum Cryptography (PQC) posture requires simultaneous mastery of cloud control-plane telemetry, quantum circuit physics, application wire-protocol constraints, and financial risk modeling. A purely generative LLM approach fails in this domain due to arithmetic hallucinations and non-deterministic scoring, whereas a purely static scanner fails to synthesize cross-layer application blast radius and consultative migration architecture. The Agentic PQC Readiness & CBOM Engine solves this via a Neuro-Symbolic Multi-Plane Architecture:"),
            ("BULLETS", [
                "Tenet 1 — Neuro-Symbolic Separation of Concerns (Cognitive Orchestration vs. Deterministic Math/Physics): The Large Language Model (Gemini 3.1 Pro / 2.5 Pro orchestrated via Google ADK) handles natural-language intent routing, stakeholder calibration synthesis, and consultative report structuring, while 100% of GCP API discovery, Shor/Roetteler/Grover/Core-SVP qubit equations, 10,000-run Monte Carlo Q-VaR simulations, and KPI percentage calculations execute inside deterministic, auditable Python engines.",
                "Tenet 2 — 100% Agentless, Zero-Plaintext Control-Plane Introspection: The system operates exclusively via read-only Google Cloud control-plane APIs. It never installs host agents, never inspects data-plane network packets, never reads Secret Manager payloads, and never accesses private cryptographic key material.",
                "Tenet 3 — Closed-Loop Self-Calibrating Intelligence: Stakeholder context captured via PQC_Discovery_Questionnaire and interactive consultant feedback (PQC_User_and_Consultant_Guide) are persisted in a longitudinal calibration ledger (tools/calibration_engine.py), allowing the agent to automatically learn from its history and refine Mosca (X + Y > Z) and Q-VaR parameters across runs.",
                "Tenet 4 — Portable Customer-Environment Template Design: Every runtime URI, project identifier, storage bucket, and IAM principal is parameterized via environment variables so the architecture can be deployed identically in a customer's single-tenant production enclave, a central governance hub, or a consultant's workstation.",
            ]),
            ("H3", "1.1 Customer Environment Parameterization Table (Engagement Template)"),
            ("P", "To instantiate this architecture in a customer's contracted Google Cloud environment, replace the template placeholders below with the customer's provisioned resource identifiers (detailed step-by-step in PQC_User_and_Consultant_Guide):"),
            ("TABLE", [
                ["Architectural Component", "Template Placeholder Variable", "Standard GCP Resource URI Pattern", "Contracted Customer Environment Value"],
                ["Target Assessment Scope (Org / Folder)", "<CUSTOMER_ORG_ID>", "organizations/<ORG_ID> or folders/<FOLDER_ID>", "[ Populate in Customer Environment ]"],
                ["Agent Host GCP Project", "<AGENT_HOST_PROJECT_ID>", "projects/<HOST_PROJECT_ID>", "[ Populate in Customer Environment ]"],
                ["Vertex AI Agent Engine Runtime", "<REASONING_ENGINE_URI>", "projects/<PROJECT_NUM>/locations/<REGION>/reasoningEngines/<ID>", "[ Populate in Customer Environment ]"],
                ["Cloud Run Web UI & SSE API Gateway", "<CLOUD_RUN_ENDPOINT_URL>", "https://<SERVICE>-<PROJECT_NUM>.<REGION>.run.app", "[ Populate in Customer Environment ]"],
                ["Dedicated Read-Only Scanner SA", "<SCANNER_SERVICE_ACCOUNT>", "pqc-scanner-sa@<HOST_PROJECT_ID>.iam.gserviceaccount.com", "[ Populate in Customer Environment ]"],
                ["Persistent Calibration & CBOM Vault", "<CALIBRATION_GCS_BUCKET>", "gs://<HOST_PROJECT_ID>-pqc-artifacts/calibration_history.jsonl", "[ Populate in Customer Environment ]"],
            ]),
            ("H2", "2. Five-Plane System Architecture & End-to-End Data Flow (C4 Container & Component View)"),
            ("P", "The platform is architected across five decoupled horizontal planes that process telemetry from raw GCP control-plane APIs into board-ready financial risk models and engineering runbooks in ~6.7 seconds:"),
            ("NUMBERED", [
                "Plane 1 — Multi-Channel Presentation, Streaming & API Gateway Layer (main.py): Asynchronous FastAPI server exposing (a) an interactive Consultative Web UI with real-time Server-Sent Events (SSE) tool-execution tracing (/api/chat/stream), (b) REST batch assessment and multi-persona export endpoints (/api/assess, /api/export), (c) native Google ADK Developer UI (/dev-ui), (d) conversational integration with Gemini Enterprise via Vertex AI Agent Engine, and (e) a headless CLI exporter for CI/CD governance pipelines.",
                "Plane 2 — Cognitive Agent Orchestration & Guardrail Plane (pqc_agent/agent.py): Powered by Google ADK (Agent Development Kit) and Vertex AI Gemini 3.1 Pro / 2.5 Pro (configured with temperature=0.1 and thinking_level=MEDIUM). Enforces strict anti-hallucination system instructions: mandatory multi-tool correlation, automatic tenant-sandbox (*-tp) scope redirection, verbatim locking of backend-computed scorecard percentages, and a standardized 6-section consultative deliverable layout.",
                "Plane 3 — Deterministic Cryptographic, Quantum Physics & Self-Calibrating Tool Plane (tools/): Comprises five specialized deterministic sub-engines invoked autonomously by the ADK agent: (3A) High-Concurrency GCP Inventory & 4-Vector Blast-Radius Engine (tools/gcp_inventory.py), (3B) Network Edge TLS 1.3 & BYOK Supply-Chain Detector Engine (tools/pqc_detectors.py), (3C) Surface-Code Quantum Physics & 10,000-Run Monte Carlo Q-VaR Engine (tools/quantum_engine.py), (3D) Historical Self-Calibration & Sector Memory Engine (tools/calibration_engine.py), and (3E) Multi-Persona Report & CycloneDX v1.6 CBOM Exporter (tools/report_exporter.py).",
                "Plane 4 — Target Google Cloud Control-Plane Telemetry Plane: Asynchronous, rate-limited, 16-worker ThreadPoolExecutor introspection across Cloud Resource Manager v3, Cloud KMS & Cloud HSM v1, Cloud Asset Inventory v1 (searchAllResources & searchAllIamPolicies), Compute Engine SSL Policies (global & regional), Certificate Authority Service (CAS) v1, GKE Cluster encryption metadata, and KMS ImportJobs.",
                "Plane 5 — Persistent Calibration Ledger & Deliverable Storage Plane: Stores longitudinal calibration events (calibration_history.jsonl), timestamped OWASP CycloneDX v1.6 CBOM JSON artifacts, and print-to-PDF HTML/Markdown Executive & Engineering reports in local storage or customer-managed Cloud Storage (gs://<CALIBRATION_GCS_BUCKET>).",
            ]),
            ("H3", "2.1 Sub-Engine Component Matrix & Cross-Document Traceability"),
            ("TABLE", [
                ["Architectural Plane & Sub-Engine", "Implementation Module", "Key Capabilities & Algorithms", "Connected Accelerator Document"],
                ["Plane 1: Presentation & SSE Gateway", "main.py / FastAPI / ADK Web", "Async SSE streaming, REST export endpoints, session state management, health probes.", "PQC_User_and_Consultant_Guide"],
                ["Plane 2: Cognitive ADK Orchestrator", "pqc_agent/agent.py", "Gemini 3.1 Pro / 2.5 Pro reasoning, 12-tool routing, zero-hallucination scorecard locking.", "PQC_Technical_Design_Document_TDD"],
                ["Plane 3A: 4-Vector Telemetry Engine", "tools/gcp_inventory.py", "16-worker ThreadPoolExecutor org scan, KMS/HSM/CAS inventory, 4-vector app blast-radius.", "PQC_Technical_Design_Document_TDD"],
                ["Plane 3B: Edge TLS & BYOK Detectors", "tools/pqc_detectors.py", "Compute SslPolicy (X25519MLKEM768) detector, ImportJob wrapping audit, Tink & OrgPolicy YAML.", "PQC_CISO_Recommendations_Book"],
                ["Plane 3C: Quantum Physics & Q-VaR", "tools/quantum_engine.py", "Gidney-Ekera Shor, Roetteler ECDLP, Grassl Grover, Core-SVP, 10k Monte Carlo Q-VaR (95%).", "PQC_CISO_Recommendations_Book"],
                ["Plane 3D: Self-Calibrating Memory", "tools/calibration_engine.py", "Sector baselines (BFSI, Healthcare, Public Sector, Telecom, OT), Mosca (X+Y>Z) ledger.", "PQC_Discovery_Questionnaire"],
                ["Plane 3E: Multi-Persona Exporter", "tools/report_exporter.py", "Generates Executive Board Report, Engineering Playbook, and OWASP CycloneDX v1.6 CBOM.", "PQC_Sample_Live_Assessment_Report"],
            ]),
            ("H2", "3. Enterprise Reference Deployment Topologies (Customer vs. Consultant Environments)"),
            ("P", "Depending on the customer's regulatory posture, data residency rules, and engagement phase, the architecture supports three validated deployment topologies (with step-by-step commands provided in PQC_User_and_Consultant_Guide):"),
            ("TABLE", [
                ["Deployment Topology", "Runtime Hosting Location", "Authentication & IAM Model", "Network & Data Isolation Boundary", "Recommended Engagement Scenario"],
                [
                    "Topology A: Customer-Hosted Single-Tenant Enclave\n(Production Recommended)",
                    "Customer's Security Operations GCP Project (Cloud Run + Vertex AI Agent Engine)",
                    "Dedicated Customer Service Account (pqc-scanner-sa) with read-only Org Viewer roles; zero external access.",
                    "Internal Load Balancer + Identity-Aware Proxy (IAP) enclosed in a VPC Service Controls (VPC-SC) perimeter.",
                    "Regulated BFSI, Healthcare, Defense, and Large Enterprise engagements requiring continuous posture monitoring."
                ],
                [
                    "Topology B: Hub-and-Spoke Cross-Organization Assessment",
                    "Central Governance Hub Project scanning multiple subsidiary Organizations/Folders",
                    "Keyless Cross-Project Service Account Impersonation (roles/iam.serviceAccountTokenCreator); short-lived 1h OAuth2 tokens.",
                    "Encrypted TLS 1.3 control-plane API calls over Google's production backbone; zero static JSON keys.",
                    "Conglomerates, M&A due diligence, or multi-org enterprises managed by a central CISO office."
                ],
                [
                    "Topology C: Ephemeral Consultant Workstation / Cloud Shell",
                    "Consultant Laptop, Cloud Shell, or PSO Lab Project",
                    "Google Cloud SDK Application Default Credentials (ADC) with --impersonate-service-account against customer SA.",
                    "Ephemeral session execution; CBOM and reports generated directly into customer's authorized workspace.",
                    "Fast-Track (1-week) discovery assessments, PoCs, and live executive workshops."
                ],
            ]),
            ("H2", "4. Closed-Loop Self-Calibration & Continuous Historical Learning Architecture"),
            ("P", "A core architectural differentiator of this AI system is its ability to self-calibrate its analytical models by learning from stakeholder discovery inputs and historical consultant feedback:"),
            ("NUMBERED", [
                "Phase 1 — Structured Context Ingestion: During stakeholder interviews (guided by PQC_Discovery_Questionnaire), the consultant executes Calibration Prompts (cataloged in PQC_User_and_Consultant_Guide). The ADK agent invokes calibrate_assessment_context(), validating and writing the organization's sector profile, confidentiality horizon (X), refactoring velocity (Y), CRQC threat window (Z), API gateway header limits, and project criticality overrides into calibration_history.jsonl.",
                "Phase 2 — Automatic Pre-Execution Memory Retrieval: Whenever a user asks the agent to assess an organization, evaluate quantum risk, or generate migration runbooks, the agent first invokes get_historical_calibration_profile(scope). This loads the cumulative historical calibration state into the active execution context without requiring the user to repeat prior constraints.",
                "Phase 3 — Dynamic Recalibration of Mosca Horizons & Q-VaR Multipliers: The retrieved calibration parameters dynamically adjust the Mosca safety margin (M = Z - (X + Y)), re-weight the 10,000-iteration Monte Carlo Q-VaR financial exposure by the sector multiplier, flag HTTP header overflow risks if gateway limits are <16KB, and prioritize Tier-0 business projects first in the 30-60-90 day execution plan.",
            ]),
            ("H2", "5. Security Architecture, Zero-Trust Threat Model (STRIDE) & Least-Privilege IAM"),
            ("H3", "5.1 Least-Privilege Read-Only IAM Permission Matrix"),
            ("TABLE", [
                ["Predefined GCP Role", "Granular API Permissions Utilized", "Architectural Purpose", "Explicitly Excluded High-Risk Permissions"],
                ["roles/cloudasset.viewer", "cloudasset.assets.searchAllResources, cloudasset.assets.searchAllIamPolicies", "4-Vector workload blast-radius mapping & folder/project discovery.", "No write, delete, or policy modification permissions."],
                ["roles/cloudkms.viewer", "cloudkms.keyRings.list, cloudkms.cryptoKeys.list, cloudkms.cryptoKeyVersions.list, cloudkms.importJobs.list", "Inspects key algorithms, HSM protection levels, rotation periods, and BYOK wrapping.", "Excludes cloudkms.cryptoKeyVersions.useToDecrypt and useToSign (zero key usage)."],
                ["roles/privateca.auditor", "privateca.caPools.list, privateca.certificateAuthorities.list", "Audits Root and Subordinate CA key specifications in Certificate Authority Service.", "Excludes privateca.certificates.create and CA private key access."],
                ["roles/compute.viewer", "compute.sslPolicies.list, compute.regionSslPolicies.list, compute.targetHttpsProxies.list", "Detects TLS 1.0/1.2 SNDL exposure vs. TLS 1.3 X25519MLKEM768 readiness.", "Excludes compute.instances.* mutation or network packet capture."],
            ]),
            ("H3", "5.2 AI Safety, Anti-Hallucination & STRIDE Threat Mitigation Controls"),
            ("BULLETS", [
                "Mitigating LLM Arithmetic & Scoring Hallucinations (Integrity): The LLM is prohibited from computing maturity percentages. All 7 KPI percentages are deterministically calculated in Python (_compute_metrics_for_keys) and locked inside validated_executive_scorecard.",
                "Cryptographic Provenance Attestation (Non-Repudiation): Every tool response embeds a data_validation_manifest with an explicit authenticity flag (LIVE_GCP_TELEMETRY_VERIFIED vs. SIMULATED_BENCHMARK_DATASET) and timestamp.",
                "Tenant Sandbox Isolation (Confidentiality): Runtime scope resolution blocks accidental scanning of internal Vertex AI *-tp tenant projects and enforces strict customer scope boundaries.",
                "Prompt Injection & Tool-Argument Sanitization (Tampering): All scope identifiers and calibration parameters are regex-sanitized and type-checked before invoking Google Cloud client libraries or shell runbook generators.",
            ]),
            ("H2", "6. Non-Functional Requirements: Scalability, Resilience, Observability & FinOps"),
            ("BULLETS", [
                "High-Concurrency Throughput & Latency SLAs: Utilizes a 16-worker ThreadPoolExecutor to scan 8–15 projects in ~6.7 seconds, scaling linearly to 100–500+ projects in <45 seconds via paginated Cloud Asset Inventory bulk queries.",
                "Graceful Degradation & Rate-Limit Resilience: Implements per-project exception isolation (if Cloud KMS or CAS API is disabled in a sandbox project, the worker records a clean status without aborting the organization scan) and exponential backoff on HTTP 429/503 responses.",
                "Vertex AI Token FinOps & Context Efficiency: Tool outputs are serialized as compact JSON (separators=(',', ':')) and paired with temperature=0.1 and thinking_level=MEDIUM, minimizing token consumption while maximizing analytical precision.",
            ]),
        ],
    },
    # -------------------------------------------------------------------------
    # 09. User and Consultant Guide — DEPLOYMENT HOW-TO + SELF-CALIBRATING PROMPTS
    # -------------------------------------------------------------------------
    {
        "doc_name": "PQC_User_and_Consultant_Guide",
        "old_names": ["09_PQC_User_and_Consultant_Guide.md", "09_PQC_User_and_Consultant_Guide"],
        "cover_title": "Post-Quantum Cryptography\u000bUser & Consultant Guide",
        "cover_subtitle": "Google Cloud Consulting (PSO) — Dual-Environment Deployment How-To & Self-Calibrating Prompt Playbook",
        "page2_headline": "Deployment, Calibration & Operational Guide: Agentic PQC Engine",
        "page2_subtitle": "Step-by-Step How-To for Consultant & Customer Environments, Calibration Prompts & Historical Self-Learning",
        "exec_summary": (
            "This operational manual is the definitive step-by-step 'How-To' guide for Google Cloud Consulting (PSO) "
            "Architects, Technical Account Managers (TAMs), GSD Engineers, and Customer Platform/Security Teams. It "
            "covers: (1) deploying and running the agent in the Consultant/Engineer environment, (2) deploying the "
            "agent into the Customer's contracted Google Cloud environment (Cloud Run & Vertex AI Agent Engine), "
            "(3) the Calibration Prompts Library to inject PQC_Discovery_Questionnaire context, and (4) how the agent "
            "automatically self-calibrates its responses by learning from its interaction history."
        ),
        "blocks": [
            ("H2", "1. Operational Workflow & Cross-Document Integration"),
            ("P", "To execute a consistent, high-margin PQC Readiness Assessment, the practitioner follows a 4-step closed-loop operational workflow that connects all documents in the Technical and Executive folders:"),
            ("NUMBERED", [
                "Step 1 — Deploy & Authenticate (Sections 2 & 3 below): Deploy the agent either in the Consultant's workstation/Cloud Shell (Topology C) or inside the Customer's contracted GCP environment (Topology A/B, as architected in PQC_System_Architecture_Specification) and bind the 4 read-only IAM roles.",
                "Step 2 — Calibrate with Stakeholder Discovery Context (Section 4 below): Conduct the 7-domain interview using PQC_Discovery_Questionnaire and run the Calibration Prompts below. The agent invokes calibrate_assessment_context() (specified in PQC_Technical_Design_Document_TDD) to persist sector parameters (X, Y, Z, gateway limits, and project overrides) into its historical ledger.",
                "Step 3 — Execute Self-Calibrated Multi-Layer Scan (Section 5 below): Run the full assessment prompt. The agent automatically retrieves its learned history via get_historical_calibration_profile(), scans all 4 GCP telemetry layers, runs the 10,000-iteration Monte Carlo Q-VaR simulation, and synthesizes the 6-part consultative report.",
                "Step 4 — Export Multi-Persona Deliverables & Execute Runbooks (Section 6 below): Export the Executive Board Report (aligned with PQC_CISO_Recommendations_Book), the Technical Engineering Playbook (5-step Cloud HSM runbooks), and the OWASP CycloneDX v1.6 CBOM (.json).",
            ]),
            ("H3", "1.1 Template Execution Channels Summary"),
            ("TABLE", [
                ["Execution Channel", "Template Endpoint / Command Pattern", "Primary Operator & Use Case"],
                ["Google ADK Developer Web UI (Local / Cloud Shell)", "adk web (http://localhost:8000 -> select pqc_inventory_agent)", "Consultant / Engineer live tool tracing, interactive calibration, and debugging."],
                ["FastAPI Consultative Web UI & SSE Server", "https://<CLOUD_RUN_SERVICE>-<PROJECT_NUM>.<REGION>.run.app", "Customer workshops, live streaming executive demos, and 1-click report downloads."],
                ["Vertex AI Agent Engine (Gemini Enterprise)", "projects/<PROJECT_NUM>/locations/<REGION>/reasoningEngines/<ENGINE_ID>", "Managed enterprise conversational access inside customer's Gemini Enterprise portal."],
                ["Headless CLI Multi-Persona Exporter", "python3 main.py --scope organizations/<CUSTOMER_ORG_ID> --export-dir ./exports", "Automated batch generation of Markdown, print-to-PDF HTML, and CycloneDX v1.6 CBOM."],
            ]),
            ("H2", "2. Part 1 — How-To: Deploying in the Consultant / Engineer Environment"),
            ("P", "Use this workflow when running the agent from a PSO Consultant laptop, Google Cloud Shell, or an isolated PSO Sandbox project to assess a customer organization via keyless Service Account impersonation:"),
            ("NUMBERED", [
                "Step 2.1 — Install Toolchain & Python Virtual Environment: Ensure Python 3.11+ and Google Cloud SDK (gcloud) are installed. Clone the accelerator repository and install locked dependencies: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt",
                "Step 2.2 — Authenticate via Keyless Application Default Credentials (ADC): Never download static Service Account JSON keys. Authenticate with your corporate identity and impersonate the customer's read-only scanner Service Account: gcloud auth application-default login --impersonate-service-account=pqc-scanner-sa@<CUSTOMER_HOST_PROJECT_ID>.iam.gserviceaccount.com",
                "Step 2.3 — Configure the Local Environment Template (.env): Create a .env file in the project root with the customer's target scope: GOOGLE_GENAI_USE_VERTEXAI=TRUE, GOOGLE_CLOUD_PROJECT=<CONSULTANT_OR_HOST_PROJECT_ID>, GOOGLE_CLOUD_LOCATION=global, PQC_AGENT_MODEL=gemini-3.1-pro-preview-customtools, PQC_TARGET_ORG_ID=organizations/<CUSTOMER_ORG_ID>, and PQC_CALIBRATION_STORE_PATH=./exports/calibration_history.jsonl.",
                "Step 2.4 — Launch Interactive ADK Web UI or FastAPI Server: Run adk web --port 8000 (for the native ADK trace inspector) OR uvicorn main:app --host 0.0.0.0 --port 8080 (for the Google Cloud Consulting styled Web UI with SSE streaming and deliverable export buttons).",
            ]),
            ("H2", "3. Part 2 — How-To: Deploying in the Customer's Contracted GCP Environment"),
            ("P", "Use this workflow when deploying the agent as a permanent or engagement-long single-tenant service inside the customer's own Google Cloud Organization (Topology A in PQC_System_Architecture_Specification):"),
            ("NUMBERED", [
                "Step 3.1 — Enable Required Control-Plane APIs in the Customer Host Project: Run gcloud services enable aiplatform.googleapis.com run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com cloudasset.googleapis.com cloudkms.googleapis.com privateca.googleapis.com compute.googleapis.com cloudresourcemanager.googleapis.com --project=<CUSTOMER_HOST_PROJECT_ID>",
                "Step 3.2 — Create the Dedicated Read-Only Scanner Service Account: Run gcloud iam service-accounts create pqc-scanner-sa --display-name=\"PQC Readiness Assessment Scanner SA\" --project=<CUSTOMER_HOST_PROJECT_ID>",
                "Step 3.3 — Bind Least-Privilege Read-Only Roles at the Customer Organization Scope: Grant the 4 metadata-only viewer roles across organizations/<CUSTOMER_ORG_ID> (for ROLE in roles/cloudasset.viewer roles/cloudkms.viewer roles/privateca.auditor roles/compute.viewer; do gcloud organizations add-iam-policy-binding <CUSTOMER_ORG_ID> --member=\"serviceAccount:pqc-scanner-sa@<CUSTOMER_HOST_PROJECT_ID>.iam.gserviceaccount.com\" --role=\"$ROLE\"; done) and grant roles/aiplatform.user on <CUSTOMER_HOST_PROJECT_ID> so the Service Account can invoke Vertex AI Gemini.",
                "Step 3.4 — Deploy to Customer Google Cloud Run (Zero-Trust Internal + IAP): Run gcloud run deploy pqc-inventory-agent --source=. --region=<REGION> --project=<CUSTOMER_HOST_PROJECT_ID> --service-account=pqc-scanner-sa@<CUSTOMER_HOST_PROJECT_ID>.iam.gserviceaccount.com --no-allow-unauthenticated --ingress=internal-and-cloud-load-balancing --set-env-vars=\"GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_PROJECT=<CUSTOMER_HOST_PROJECT_ID>,GOOGLE_CLOUD_LOCATION=global,PQC_TARGET_ORG_ID=organizations/<CUSTOMER_ORG_ID>\"",
                "Step 3.5 — Deploy to Vertex AI Agent Engine (Reasoning Engine / Gemini Enterprise): Run adk deploy agent_engine --project=<CUSTOMER_HOST_PROJECT_ID> --region=<REGION> --staging_bucket=gs://<CUSTOMER_STAGING_BUCKET> pqc_agent. Record the output resource URI (projects/<PROJECT_NUM>/locations/<REGION>/reasoningEngines/<ENGINE_ID>) in the Customer Configuration Manifest of PQC_Technical_Design_Document_TDD and PQC_System_Architecture_Specification.",
            ]),
            ("H2", "4. Part 3 — Calibration Prompts Library (Sector, Mosca X+Y>Z & Constraint Tuning)"),
            ("P", "Before running the final executive readout, use the copy-pasteable Calibration Prompts below to feed the answers collected from PQC_Discovery_Questionnaire into the agent. Each prompt triggers calibrate_assessment_context() so the agent stores and learns the customer's exact context:"),
            ("TABLE", [
                ["Calibration Scenario", "Target Discovery Domains", "Copy-Paste Calibration Prompt for ADK Web UI / Gemini Enterprise"],
                [
                    "1. Industry Sector & Mosca (X, Y, Z) Baseline Calibration",
                    "Domains 1, 2 & 7\n(Sector, Shelf-Life X, Velocity Y)",
                    "Calibrate the PQC assessment context for scope organizations/<CUSTOMER_ORG_ID> with industry_sector='<BFSI_BANKING | HEALTHCARE_GENOMICS | PUBLIC_SECTOR_DEFENSE | TELECOM_5G_CLOUD | ENERGY_OT_INDUSTRIAL>', confidentiality_years_x=<X_YEARS>, migration_years_y=<Y_YEARS>, and crqc_horizon_years_z=<Z_YEARS>. Persist this baseline in the historical calibration ledger and display the resulting Mosca safety margin (Z - (X+Y)) and active regulatory frameworks."
                ],
                [
                    "2. API Gateway HTTP Header & JWT Buffer Calibration",
                    "Domains 4 & 5\n(JWT Signing & Proxy Limits)",
                    "Update the calibration profile for organizations/<CUSTOMER_ORG_ID>: our API Gateways and Envoy/NGINX proxies currently enforce gateway_header_limit_kb=<4 | 8 | 16 | 32>. Evaluate whether 3,309-byte ML-DSA-65 JWT signatures (~4.4 KB Base64URL) will trigger HTTP 431 Request Header Fields Too Large errors and calibrate all engineering runbooks accordingly."
                ],
                [
                    "3. Project-Tier Criticality & Crown-Jewel Override Calibration",
                    "Domains 2 & 3\n(Business Unit Prioritization)",
                    "Calibrate project_tier_overrides for organizations/<CUSTOMER_ORG_ID>: classify projects [<TIER_0_PROJECT_IDS>] as Tier-0 Crown-Jewel workloads with X=<25> years confidentiality requirement, and projects [<SANDBOX_PROJECT_IDS>] as Tier-3 non-production sandboxes. Ensure all subsequent Q-VaR simulations and 30-60-90 day workstreams prioritize Tier-0 keys first."
                ],
                [
                    "4. Compensating Controls & BYOK/VPC-SC Calibration",
                    "Domains 2, 3 & 6\n(VPC-SC, HSM & Exceptions)",
                    "Record compensating_controls_note for organizations/<CUSTOMER_ORG_ID>: '<e.g., BigQuery datasets in project X are enclosed in a VPC-SC perimeter; legacy RSA key Y is scheduled for decommissioning in 30 days>'. Recalibrate our historical posture profile and adjust remediation urgency."
                ],
                [
                    "5. Inspect Learned Historical Calibration Ledger",
                    "All Domains\n(Governance & Drift Verification)",
                    "Retrieve the active historical calibration profile for organizations/<CUSTOMER_ORG_ID> using get_historical_calibration_profile. Summarize all learned parameters, historical calibration events, active Mosca (X+Y vs Z) verdicts, and sector Q-VaR multipliers currently governing the agent."
                ],
                [
                    "6. Full Self-Calibrated Assessment & Deliverable Export",
                    "All 4 Telemetry Layers + Learned Calibration",
                    "Run a complete, self-calibrated Post-Quantum Cryptography (PQC) Readiness Assessment and Step-by-Step Execution Guide for organizations/<CUSTOMER_ORG_ID>. First load our learned historical calibration profile, then correlate scan_organization_pqc_readiness, scan_ssl_policies, scan_import_jobs_pqc, and run_quantum_cryptanalysis_simulation, and export all Executive, Engineering, and CycloneDX v1.6 CBOM deliverables."
                ],
            ]),
            ("H2", "5. Part 4 — How Automated Self-Calibration & Continuous Historical Learning Work"),
            ("P", "The Agentic PQC Readiness & CBOM Engine is engineered so that its responses automatically self-calibrate over time by learning from its interaction history (implemented in tools/calibration_engine.py and enforced by SYSTEM_INSTRUCTION in pqc_agent/agent.py):"),
            ("BULLETS", [
                "1. Persistent Longitudinal Memory (calibration_history.jsonl): Every time a consultant or customer engineer provides organizational context, answers a discovery question, or overrides a parameter (such as adjusting X from 10 to 25 years for biometric data or noting an 8KB Apigee header limit), the agent invokes calibrate_assessment_context() to append a structured JSON event to the calibration ledger.",
                "2. Automatic Pre-Scan Recall (Zero Re-Prompting Required): Under Mandatory Rule #2 of the agent's system instruction, before generating any readiness assessment or quantum risk simulation, the agent automatically calls get_historical_calibration_profile(scope). It reads the cumulative calibration history for that organization, extracts the most recent sector multipliers, Mosca (X, Y, Z) horizons, gateway constraints, and compensating controls, and applies them automatically.",
                "3. Progressive Refinement Across Engagement Phases: In Week 1 (Mobilization), the agent starts with the industry vertical baseline (e.g., BFSI_BANKING: X=15y, Y=3y). In Week 2 (Deep Discovery), as application and PKI owners refine gateway limits and project tiers via Calibration Prompts 2–4, the agent's risk rankings, Q-VaR figures, and refactoring runbooks automatically adapt to reflect the newly learned architectural reality.",
                "4. Multi-Customer Isolation & Ledger Reset: Each calibration entry is keyed by scope (organizations/<CUSTOMER_ORG_ID>). When starting an engagement for a new customer, specifying the new Organization ID or pointing PQC_CALIBRATION_STORE_PATH to a dedicated customer bucket guarantees 100% tenant isolation.",
            ]),
            ("H2", "6. Part 5 — Operational Troubleshooting & Post-Execution Verification Checklist"),
            ("TABLE", [
                ["Symptom / Error Code", "Root Cause Analysis", "Prescriptive Resolution Command / Action"],
                ["HTTP 403 PERMISSION_DENIED on Cloud KMS or CAI", "Scanner Service Account lacks organization-level viewer bindings or impersonation permission.", "Verify roles/cloudasset.viewer and roles/cloudkms.viewer on organizations/<CUSTOMER_ORG_ID> and roles/iam.serviceAccountTokenCreator for impersonation."],
                ["Agent attempts to scan project-*-tp sandbox", "Vertex AI Agent Engine injects its internal runtime tenant project ID by default.", "Resolved automatically by _resolve_scope() in tools/gcp_inventory.py; always pass organizations/<CUSTOMER_ORG_ID> explicitly in prompts."],
                ["HTTP 429 RESOURCE_EXHAUSTED on Vertex AI", "Concurrent tool payloads or regional Gemini quota saturation.", "Set GOOGLE_CLOUD_LOCATION=global when using gemini-3.1-pro-preview-customtools or switch PQC_AGENT_MODEL to gemini-2.5-pro."],
                ["VPC Service Controls (VPC-SC) Violation", "Customer perimeter blocks ingress from external workstation or Cloud Run service.", "Deploy the agent inside the customer's VPC-SC perimeter (Topology A) or add an ingress policy allowing pqc-scanner-sa."],
            ]),
        ],
    },
    # -------------------------------------------------------------------------
    # 11. Sample Live Assessment Report (+ Other Document field)
    # -------------------------------------------------------------------------
    {
        "doc_name": "PQC_Sample_Live_Assessment_Report_31564119954",
        "old_names": ["11_PQC_Sample_Live_Assessment_Report_31564119954.md", "11_PQC_Sample_Live_Assessment_Report_31564119954"],
        "cover_title": "Post-Quantum Cryptography\u000bLive Assessment Report",
        "cover_subtitle": "Google Cloud Consulting (PSO) — Exemplar Benchmark Output (Org 31564119954)",
        "page2_headline": "Executive & Technical PQC Assessment Report (Benchmark Exemplar)",
        "page2_subtitle": "Validated Scorecard, Monte Carlo Q-VaR ($10.32M -> $0.15M) & 5-Step Cloud HSM Runbooks",
        "exec_summary": (
            "This document serves as a concrete Golden Sample (exemplar output) generated by a live execution of the "
            "Agentic PQC Readiness & CBOM Engine across reference benchmark Organization 31564119954, demonstrating "
            "deterministic scorecard validation, 10,000-run Monte Carlo Q-VaR ($10.32M exposure -> $0.15M mitigated), "
            "and copy-pasteable 5-step Cloud HSM runbooks."
        ),
        "blocks": [
            ("H2", "1. Executive Summary (BLUF) & Validated Scorecard"),
            ("P", "Authenticity Attestation: LIVE_GCP_TELEMETRY_VERIFIED | Quantum Engine: 2.0.0-GidneyEkera-Roetteler-CoreSVP-Validated."),
            ("TABLE", [
                ["Executive KPI / Posture Metric", "Validated Value", "Target Benchmark", "Consultative Assessment"],
                ["Weighted PQC Maturity Score", "70.0%", "100.0%", "MODERATE — Immediate action required on asymmetric keys"],
                ["Asymmetric Migration Score (Shor Immunity)", "50.0% (2/4 keys)", "100.0%", "CRITICAL — ECDSA P-256 & RSA-2048 exposed to Shor/HNDL"],
                ["Symmetric Data-at-Rest (Grover Resilience)", "100.0% (6/6 keys)", "100.0%", "COMPLIANT — AES-256 provides 128-bit post-quantum security"],
                ["Symmetric Rotation Hygiene (<= 90 Days)", "66.7% (4/6 keys)", "100.0%", "ACTION REQUIRED — 2 AES-256 keys lack 90-day rotation"],
                ["SSL/TLS Edge Readiness (X25519MLKEM768)", "50.0%", "100.0%", "ACTION REQUIRED — Upgrade TLS 1.0/1.2 policies to TLS 1.3"],
                ["Monte Carlo Q-VaR (95% Financial Exposure)", "US$ 10.32M -> US$ 0.15M", "< US$ 0.25M", "98.5% Risk Reduction upon PQC Remediation"],
            ]),
            ("H2", "2. Quantum Physics Cryptanalysis & Fall-Order Ranking"),
            ("TABLE", [
                ["Fall Order", "Asset Name (Project / KeyRing)", "Algorithm", "Logical / Physical Qubits", "Estimated Break Time & Risk"],
                ["1st to Fall", "jwt-signing-ecdsa-key (auth-kr)", "EC_SIGN_P256_SHA256", "2,330 Logical / ~13.4M Physical", "~9.5 Hours on CRQC — P0 Immediate"],
                ["2nd to Fall", "legacy-payment-rsa-key (payments-kr)", "RSA_DECRYPT_OAEP_2048_SHA256", "4,098 Logical / ~20.0M Physical", "~8.0 Hours on CRQC — P1 Active HNDL"],
                ["Quantum-Safe", "pqc-hybrid-kem-key (payments-kr)", "KEM_XWING (X25519 + ML-KEM-768)", "Core-SVP 167-Bit Lattice", "Quantum-Safe (NIST FIPS 203 Hybrid)"],
                ["Quantum-Safe", "pqc-mldsa-signing-key (auth-kr)", "PQ_SIGN_ML_DSA_65", "Core-SVP 166-Bit Lattice", "Quantum-Safe (NIST FIPS 204 Level 3)"],
            ]),
            ("H2", "3. Consultative 5-Step Remediation Runbooks (100% of Vulnerable Keys)"),
            ("H3", "3.1 Runbook 1 — jwt-signing-ecdsa-key (EC_SIGN_P256_SHA256 -> PQ_SIGN_ML_DSA_65)"),
            ("NUMBERED", [
                "Step 1 — Provision PQC Key in Cloud HSM: gcloud kms keys create jwt-signing-ecdsa-key-pqc --keyring=auth-kr --location=global --purpose=asymmetric-signing --default-algorithm=pq-sign-ml-dsa-65 --protection-level=hsm --project=<TARGET_PROJECT_ID>",
                "Step 2 — Replicate Least-Privilege IAM Binding: gcloud kms keys add-iam-policy-binding jwt-signing-ecdsa-key-pqc --keyring=auth-kr --location=global --member=\"serviceAccount:Workload-SA@<TARGET_PROJECT_ID>.iam.gserviceaccount.com\" --role=\"roles/cloudkms.signerVerifier\"",
                "Step 3 — Gateway & JWT Header Adaptation: Increase max_request_headers_kb to 16KB-32KB in Envoy/Cloud Armor/NGINX to accommodate 3,309-byte ML-DSA-65 signatures.",
                "Step 4 — Dual-Signing Canary Cutover: Publish both ECDSA P-256 and ML-DSA-65 public keys in JWKS endpoint during canary rollout.",
                "Step 5 — Post-Change Verification & Legacy Disablement: Run gcloud kms keys versions list --key=jwt-signing-ecdsa-key-pqc --keyring=auth-kr --location=global and disable legacy version via gcloud kms keys versions disable 1 --key=jwt-signing-ecdsa-key --keyring=auth-kr --location=global.",
            ]),
            ("H3", "3.2 Runbook 2 — legacy-payment-rsa-key (RSA_2048 -> KEM_XWING / ML-KEM-768)"),
            ("NUMBERED", [
                "Step 1 — Provision Hybrid PQC KEM Key in Cloud HSM: gcloud kms keys create legacy-payment-rsa-key-pqc --keyring=payments-kr --location=us-central1 --purpose=key-encapsulation --default-algorithm=kem-xwing --protection-level=hsm --project=<TARGET_PROJECT_ID>",
                "Step 2 — Replicate Least-Privilege IAM Binding: Grant roles/cloudkms.cryptoOperator to the payment workload Service Account.",
                "Step 3 — Refactor AsymmetricDecrypt to KEM Decapsulate / Google Tink: Replace raw RSA decryption calls with Cloud KMS Decapsulate() or Google Tink AEAD envelope encryption.",
                "Step 4 — Historical Data Re-Encryption (HNDL Mitigation): Re-wrap stored payment archives encrypted under RSA-2048 using AES-256-GCM DEKs protected by KEM_XWING.",
                "Step 5 — Post-Change Verification & Legacy Disablement: Verify ENABLED state via gcloud kms keys versions list and disable the classical RSA-2048 version.",
            ]),
        ],
    },
    # -------------------------------------------------------------------------
    # 12. README (Repository & Accelerator Overview)
    # -------------------------------------------------------------------------
    {
        "doc_name": "README",
        "old_names": ["README.md"],
        "cover_title": "Post-Quantum Cryptography\u000bAccelerator Overview",
        "cover_subtitle": "Google Cloud Consulting (PSO) — Master Repository & Deliverable Index",
        "page2_headline": "Accelerator Master Guide & PQC Architecture Navigation Map",
        "page2_subtitle": "Structured Index by Folder (Executive, Technical, and Pitch), Concise Deliverable Summaries & Architectural Roles",
        "exec_summary": (
            "This master README serves as the central navigation compass for the Google Cloud Consulting (PSO) "
            "Post-Quantum Cryptography (PQC) Accelerator. All strategic, commercial, and engineering deliverables are "
            "organized into three thematic folders — Executive, Technical, and Pitch — enabling CISOs, Cloud Architects "
            "(PSO/TAM/FSR), and Security Engineers to understand end-to-end the template-driven Agentic PQC Readiness & "
            "CBOM Engine, its 7-domain sector calibration model, its deterministic quantum physics engine (Shor, Grover, "
            "Core-SVP, and Monte Carlo Q-VaR 95%), its closed-loop self-calibrating memory, and its prescriptive migration "
            "runbooks for Google Cloud HSM, Google Tink, Cloud Load Balancing TLS 1.3 (X25519MLKEM768), and CycloneDX v1.6."
        ),
        "blocks": [
            ("H2", "1. Consolidated Document Map & Role in Understanding the PQC Architecture"),
            ("P", "The table below summarizes every deliverable in the accelerator, its assigned folder, a concise summary of its content, and the exact role it plays in understanding, calibrating, deploying, and executing the PQC architecture:"),
            ("TABLE", [
                ["Folder & Deliverable", "Target Audience", "Concise Content Summary", "Role in Understanding the PQC Architecture"],
                [
                    "[Pitch]\nPQC_Executive_Presentation_Deck_GCC_Ideation (Slides)",
                    "CISO, CIO, Board, GCC Leadership",
                    "12-slide executive deck covering the HNDL threat, 4-layer discovery architecture, quantum physics engine, and enterprise benchmark.",
                    "Visual entry point to the architecture: translates Shor/Grover physics, 7-second discovery, and financial ROI (Q-VaR -98.5%) in 15 minutes."
                ],
                [
                    "[Pitch]\nPQC_Elevator_Pitch_and_Lab_Prompts",
                    "FSRs, CEs, PSO Consultants, TAMs",
                    "60-second C-Level elevator pitch, customer objection battlecard, and ready-to-run template prompts for live demos in Gemini Enterprise and Web UI.",
                    "Bridges architectural theory and live interactive practice: demonstrates how to trigger each deterministic ADK tool during a customer demo."
                ],
                [
                    "[Pitch]\nPQC_Kickoff_Engagement_Deck",
                    "Executive Sponsor, CISO, Customer Team",
                    "Structured kickoff workshop guide covering quantum urgency, Zero-Data IAM scope, stakeholder alignment, and the 4-week delivery schedule.",
                    "Aligns architectural expectations on Day 1: explains how the agent inspects control-plane metadata without ever accessing private keys or plaintext."
                ],
                [
                    "[Executive]\nSOW_PQC_Readiness_Assessment_Template",
                    "Procurement, Legal, CISO, PSO Directors",
                    "Standardized 4-phase Statement of Work (SOW) template defining contractual deliverables, acceptance criteria, RACI matrix, and IAM prerequisites.",
                    "Formalizes the architecture as a consulting service contract: defines scope boundaries, read-only IAM roles, and architectural outputs."
                ],
                [
                    "[Executive]\nPQC_CISO_Recommendations_Book",
                    "CISO, Chief Risk Officer, Audit Committee",
                    "Strategic board book with the 7-KPI Scorecard, Monte Carlo Q-VaR (95%) simulation, ECDSA vs. RSA fall-order proof, GCP BOM, and 30-60-90 day plan.",
                    "Translates technical architecture into board-level investment decisions: justifies the 5-product Google Cloud target architecture BOM."
                ],
                [
                    "[Executive]\nPQC_Delivery_Model_and_Sizing_Guide",
                    "PSO Practice Leads, TAMs, Delivery Partners",
                    "Operational model across 3 T-Shirt sizing tiers (Small/Medium/Large), staffing allocation, GSD integration, and RACI governance.",
                    "Sizes the architectural implementation effort according to organizational complexity (number of GCP projects, KMS keys, and consuming apps)."
                ],
                [
                    "[Executive]\nPQC_Sample_Live_Assessment_Report_31564119954",
                    "CISO, Security Architects, GRC Leads",
                    "Complete exemplar live assessment report demonstrating real telemetry across 52 crypto assets, 22 workloads, SSL policies, and BYOK ImportJobs.",
                    "Materializes the final output of the architecture: serves as the concrete Golden Sample of the executive and engineering deliverable."
                ],
                [
                    "[Technical]\nPQC_System_Architecture_Specification",
                    "Cloud Architects, Security Engineers, SREs",
                    "Template-driven L300/L400 specification of the 5-plane neuro-symbolic AI topology, VPC-SC deployment patterns, self-calibrating memory, and STRIDE threat model.",
                    "Foundational system architecture blueprint: details internal platform design, customer template parameterization, and least-privilege IAM boundaries."
                ],
                [
                    "[Technical]\nPQC_Technical_Design_Document_TDD",
                    "Software Engineers, Cryptographers, DevSecOps",
                    "Deep L400 specification of the 12 ADK tools, 4-vector CAI correlation, Gidney-Ekera/Roetteler/Grassl equations, self-calibration ledger, and SDK refactoring.",
                    "Defines the mathematical core and low-level code contracts of the architecture with blank customer deployment template fields."
                ],
                [
                    "[Technical]\nPQC_Discovery_Questionnaire",
                    "PSO Architects, Sector Leads, App & PKI Owners",
                    "Rigorous 7-domain posture verification questionnaire with a 5-vertical Sector Calibration Matrix (BFSI, Healthcare, Public Sector, Telecom, OT/Energy).",
                    "Supplies sector-calibrated human and organizational parameters (X, Y, Z, gateway header limits) into the agent's self-calibrating memory engine."
                ],
                [
                    "[Technical]\nPQC_User_and_Consultant_Guide",
                    "PSO Consultants, DevSecOps Operators, Customer SREs",
                    "Step-by-step How-To for deploying in both Consultant and Customer GCP environments, Calibration Prompts Library, and self-learning history guide.",
                    "Operational manual for the architecture: teaches practitioners how to deploy the agent, run calibration prompts, and execute 5-step HSM runbooks."
                ],
                [
                    "[Technical]\nmain.py & requirements.txt",
                    "Platform Engineers, DevSecOps",
                    "Asynchronous FastAPI server (Web UI + SSE streaming + REST export endpoints) and validated Python dependency manifest.",
                    "Executable implementation of the presentation and orchestration layer exposing the ADK agent on Google Cloud Run."
                ],
            ]),
            ("H2", "2. Folder-by-Folder Breakdown: Summary & Architectural Role of Each Deliverable"),
            ("H3", "2.1 Pitch Folder — Strategic Positioning, Initial Engagement & Live Demonstration"),
            ("BULLETS", [
                "PQC_Executive_Presentation_Deck_GCC_Ideation (Google Slides — 12 Slides): Executive presentation built on the official Google Cloud 2026 Playbook template covering the Harvest Now, Decrypt Later (HNDL) threat, the 4-layer agentic architecture, the quantum physics engine, and the validated benchmark. Architectural Role: Serves as the L100/L200 visual entry point connecting regulatory urgency (NIST IR 8547 Final, EO 14412, and UK NCSC) to automated discovery and remediation on Google Cloud.",
                "PQC_Elevator_Pitch_and_Lab_Prompts (Google Docs): Combines the 60-second C-Level elevator pitch, sales & technical objection battlecard, and ready-to-use template prompts for live demonstrations. Architectural Role: Demonstrates in practice how to interact with the cognitive layer (Gemini 3.1 Pro + Google ADK) to trigger 4-vector discovery, quantum cryptanalysis simulation, and code refactoring runbooks.",
                "PQC_Kickoff_Engagement_Deck (Google Docs): Consultative guide for leading the customer kickoff meeting, detailing objectives, Zero-Data Access telemetry collection, stakeholder roles, and the 4-week delivery schedule. Architectural Role: Establishes architectural trust with the customer's security team by proving the agent operates strictly on control-plane metadata (IAM/CAI/KMS) without ever touching private keys or plaintext payloads.",
            ]),
            ("H3", "2.2 Executive Folder — C-Suite Governance, Financial Risk (Q-VaR) & Contracts"),
            ("BULLETS", [
                "SOW_PQC_Readiness_Assessment_Template (Google Docs): Standard Statement of Work (SOW) template for a 4-to-6 week Google Cloud Consulting engagement specifying 4 delivery phases, contractual deliverables, acceptance criteria, and RACI governance. Architectural Role: Translates technical architectural components into formal consulting work packages and defines organizational prerequisites.",
                "PQC_CISO_Recommendations_Book (Google Docs): Board-ready advisory book presenting the deterministic 7-KPI Scorecard, 10,000-iteration Monte Carlo Q-VaR (95%) financial model, physical proof of why ECDSA P-256 (2,330 logical qubits) falls before RSA-2048 (4,098 logical qubits), the 5-product Google Cloud Security BOM, and the 30-60-90 day plan. Architectural Role: Defines the Recommended Target Architecture on Google Cloud (Cloud HSM FIPS 140-3 Level 3, Google Tink SDK, VPC Service Controls, Certificate Authority Service + Load Balancing TLS 1.3 X25519MLKEM768, and Binary Authorization + SCC Enterprise/Wiz).",
                "PQC_Delivery_Model_and_Sizing_Guide (Google Docs): Commercial and technical sizing guide across Small, Medium, and Large tiers, integrating Global Security Delivery (GSD) specialists and Technical Account Managers (TAMs). Architectural Role: Guides how to scale PQC architectural implementation according to organization size, number of GCP projects, and application complexity.",
                "PQC_Sample_Live_Assessment_Report_31564119954 (Google Docs): Complete exemplar of the executive and technical assessment generated by the agent across the reference benchmark environment. Architectural Role: Serves as the tangible Golden Sample of the architecture's final output, uniting the C-Level executive readout with the 5-step Cloud HSM engineering runbooks.",
            ]),
            ("H3", "2.3 Technical Folder — System Architecture, TDD, Calibrated Discovery & Deployment How-To"),
            ("BULLETS", [
                "PQC_System_Architecture_Specification (Google Docs): Template-driven L300/L400 architectural specification detailing the 5-plane neuro-symbolic topology (Presentation/SSE, ADK Gemini 3.1 Pro Orchestration, Deterministic Tools, GCP Control-Plane Introspection, and Persistent Calibration Ledger), 3 enterprise deployment topologies (Customer Single-Tenant VPC-SC, Hub-and-Spoke, and Consultant Workstation), and STRIDE zero-trust security model. Architectural Role: Serves as the reusable system architecture blueprint to stamp into any customer engagement.",
                "PQC_Technical_Design_Document_TDD (Google Docs): Deep L400 Technical Design Document with blank customer deployment configuration fields, specifying all 12 ADK tool contracts, 4-vector CAI correlation algorithms, peer-reviewed quantum circuit formulas (Gidney-Ekera 2021, Roetteler et al. 2017, Grassl et al., Core-SVP), the self-calibrating memory engine (tools/calibration_engine.py), OWASP CycloneDX v1.6 CBOM generation, and application refactoring patterns. Architectural Role: Details the mathematical and low-level software engineering core of the platform.",
                "PQC_Discovery_Questionnaire (Google Docs): Rigorous 7-domain posture verification and calibration questionnaire featuring an Industry Sector Calibration Matrix (BFSI, Healthcare/Genomics, Public Sector/Defense, Telecom/5G, and Energy/OT) and 35+ deep verification questions with a Level 1–5 maturity rubric. Architectural Role: Captures sector-specific regulatory, PKI, HSM, and application context to calibrate Mosca's Inequality (X + Y > Z) and the agent's historical learning ledger.",
                "PQC_User_and_Consultant_Guide (Google Docs): Complete step-by-step How-To guide for deploying the agent both in the Consultant/Engineer environment (ADC impersonation, adk web, CLI) and in the Customer's contracted GCP environment (Cloud Run + IAP, Vertex AI Agent Engine), coupled with the 6-Prompt Calibration Library and documentation of the automated historical self-calibration workflow. Architectural Role: Enables PSO consultants and customer engineers to deploy, calibrate, and operate the platform autonomously.",
                "main.py & requirements.txt (Source Code & Runtime Manifest): Implementation of the asynchronous FastAPI server with Server-Sent Events (SSE) streaming, REST assessment/export endpoints, and validated Python dependencies. Architectural Role: Materializes the cloud execution layer hosting the interactive web interface and orchestrating the ADK agent.",
            ]),
            ("H2", "3. Recommended Reading Path for End-to-End Architectural Understanding"),
            ("NUMBERED", [
                "Step 1 — Executive Vision & Live Demo (Pitch Folder): Start with PQC_Executive_Presentation_Deck_GCC_Ideation (Slides) and PQC_Elevator_Pitch_and_Lab_Prompts to understand the business problem (HNDL / NIST IR 8547 Final / EO 14412) and see the agent in action.",
                "Step 2 — Deep System Architecture & Quantum Physics (Technical Folder): Read PQC_System_Architecture_Specification and PQC_Technical_Design_Document_TDD to master the 5-plane neuro-symbolic topology, 4-vector Cloud Asset Inventory blast-radius mapping, physical qubit / Q-VaR modeling, and template parameterization.",
                "Step 3 — Sector-Calibrated Discovery & Engagement Scoping (Technical & Executive Folders): Use PQC_Discovery_Questionnaire, PQC_Kickoff_Engagement_Deck, SOW_PQC_Readiness_Assessment_Template, and PQC_Delivery_Model_and_Sizing_Guide to interview stakeholders across all 7 domains and scope the customer project.",
                "Step 4 — Dual-Environment Deployment, Self-Calibration & Remediation (Technical & Executive Folders): Follow PQC_User_and_Consultant_Guide to deploy the agent in the consultant or customer environment, execute the Calibration Prompts so the agent learns and self-calibrates from its history, generate the assessment deliverables modeled on PQC_Sample_Live_Assessment_Report_31564119954, and present the modernization roadmap using PQC_CISO_Recommendations_Book.",
            ]),
        ],
    },
]



def verify_all_outputs(token, summary):
    print("\n>>> Running post-build Anti-Overlap & Anti-Hallucination verification...")
    forbidden_doc_terms = ["lorem ipsum", "ut wisi", "accenture", "dolor sit", "mirum est"]
    forbidden_slide_terms = ["mídia generativa", "veo", "nano-banana", "nano banana", "lyria", "elysco"]

    for name, meta in summary.items():
        fid = meta["id"]
        if "Slides" in name or "Presentation_Deck" in name:
            pres = api_json("GET", f"https://slides.googleapis.com/v1/presentations/{fid}", token)
            slides = pres.get("slides", [])
            all_txt = json.dumps(slides, ensure_ascii=False).lower()
            bad = [w for w in forbidden_slide_terms if w in all_txt]
            print(f"  [VERIFY SLIDES] {name}: slides={len(slides)} forbidden_terms={bad}")
            if bad:
                raise RuntimeError(f"Forbidden template residue {bad} found in Slides {name}!")
        else:
            doc = api_json("GET", f"https://docs.googleapis.com/v1/documents/{fid}", token)
            body_str = json.dumps(doc.get("body", {}), ensure_ascii=False).lower()
            bad = [w for w in forbidden_doc_terms if w in body_str]
            pos_objs = list(doc.get("positionedObjects", {}).keys())
            inline_objs = list(doc.get("inlineObjects", {}).keys())
            has_floating_body_obj = "z.000000000.i.4" in body_str
            print(
                f"  [VERIFY DOC] {name}: headers={len(doc.get('headers', {}))} "
                f"footers={len(doc.get('footers', {}))} inlineObjs={len(inline_objs)} "
                f"floatingBodyObj={has_floating_body_obj} forbidden={bad}"
            )
            if bad or has_floating_body_obj:
                raise RuntimeError(f"Doc {name} failed verification: bad={bad} floating={has_floating_body_obj}")


def main():
    token = get_token()
    output_summary = {}

    # 1. Build all 11 Cloudstyle Google Docs
    for spec in DOCUMENTS_SPEC:
        doc_name = spec["doc_name"]
        print(f">>> Cloning Official Cloudstyle Doc Template & populating: {doc_name} ...")
        cloned = clone_file_and_replace_old(
            token,
            OFFICIAL_DOC_TEMPLATE_ID,
            PQC_FOLDER_ID,
            doc_name,
            old_names=spec.get("old_names", []),
        )
        new_id = cloned["id"]
        populate_cloudstyle_doc(
            token,
            new_id,
            spec["cover_title"],
            spec["cover_subtitle"],
            spec["page2_headline"],
            spec["page2_subtitle"],
            spec["exec_summary"],
            spec["blocks"],
        )
        output_summary[doc_name] = {
            "id": new_id,
            "name": doc_name,
            "webViewLink": cloned.get("webViewLink", f"https://docs.google.com/document/d/{new_id}/edit"),
        }
        print(f"    [OK] {doc_name} -> {output_summary[doc_name]['webViewLink']}")

    # 2. Build Official Google Slides Presentation Deck
    slides_name = "10_PQC_Executive_Presentation_Deck_GCC_Ideation"
    print(f">>> Cloning Official Google Slides Playbook Template & populating: {slides_name} ...")
    res_slides = build_official_slides_presentation(
        token,
        PQC_FOLDER_ID,
        slides_name,
        old_names=[slides_name],
    )
    output_summary[slides_name] = res_slides
    print(f"    [OK] {slides_name} -> {res_slides['webViewLink']}")

    # 3. Verify all outputs for zero overlap & zero template residue
    verify_all_outputs(token, output_summary)

    print("\n=== ALL OFFICIAL CLOUDSTYLE DOCS & SLIDES COMPLETED & VERIFIED ===")
    print(json.dumps(output_summary, indent=2))


if __name__ == "__main__":
    main()
