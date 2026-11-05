"""Gemini Enterprise Dark-Theme Web UI for the Google Cloud Agentic PQC Workspace Portal."""

PORTAL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Agentic PQC Workspace Portal</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;600&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/dompurify@3.1.6/dist/purify.min.js"></script>
  <style>
    :root {
      /* Exact Gemini Enterprise Dark Palette sampled from reference */
      --bg-canvas: #131415;
      --bg-sidebar: #202020;
      --bg-pill: #2a2a2a;
      --bg-card: #2c2c2c;
      --bg-composer: #202020;
      --bg-banner: #171717;
      --bg-hover: #2f3031;
      --border-subtle: rgba(255, 255, 255, 0.08);
      --text-primary: #e3e3e3;
      --text-secondary: #c4c7c5;
      --text-muted: #8e918f;
      --gemini-blue: #4c8df6;
      --gemini-link: #8ab4f8;
      --green: #34d399;
      --danger: #f28b82;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: 'Google Sans', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: var(--bg-canvas);
      color: var(--text-primary);
      height: 100vh;
      overflow: hidden;
      display: flex;
      -webkit-font-smoothing: antialiased;
    }

    /* Left Sidebar (#202020) */
    .sidebar {
      width: 280px;
      background: var(--bg-sidebar);
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
      height: 100vh;
      padding: 14px 12px;
      gap: 10px;
      user-select: none;
    }

    .sidebar-brand-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 4px 8px 8px;
    }

    .brand-title {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 17px;
      font-weight: 500;
      color: var(--text-primary);
      letter-spacing: -0.01em;
      cursor: pointer;
      transition: opacity 0.15s ease;
    }

    .brand-title:hover {
      opacity: 0.85;
    }

    .gemini-sparkle {
      width: 22px;
      height: 22px;
      flex-shrink: 0;
    }

    /* Rounded Pill Button (#2a2a2a) */
    .btn-new-assessment {
      width: 100%;
      padding: 11px 16px;
      border-radius: 999px;
      border: none;
      background: var(--bg-pill);
      color: var(--text-primary);
      font-family: inherit;
      font-weight: 500;
      font-size: 13.5px;
      display: flex;
      align-items: center;
      gap: 12px;
      cursor: pointer;
      transition: background 0.15s ease;
    }

    .btn-new-assessment:hover {
      background: #333436;
    }

    /* Search Row styled like Gemini Enterprise nav item */
    .search-nav-row {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 8px 14px;
      border-radius: 999px;
      color: var(--text-secondary);
      transition: background 0.15s ease;
    }

    .search-nav-row:hover,
    .search-nav-row:focus-within {
      background: var(--bg-pill);
    }

    .search-nav-row input {
      width: 100%;
      border: none;
      background: transparent;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 13.5px;
      outline: none;
    }

    .search-nav-row input::placeholder {
      color: var(--text-secondary);
    }

    .sidebar-section-header {
      padding: 12px 14px 4px;
      font-size: 12px;
      font-weight: 500;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    /* Phase Items in Sidebar with Colored Avatar Circles (like Gemini Enterprise Agents) */
    .phase-nav-list {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .phase-nav-item {
      width: 100%;
      border: none;
      background: transparent;
      color: var(--text-secondary);
      font-family: inherit;
      font-size: 13px;
      padding: 7px 12px;
      border-radius: 999px;
      display: flex;
      align-items: center;
      gap: 11px;
      cursor: pointer;
      text-align: left;
      transition: background 0.12s ease, color 0.12s ease;
    }

    .phase-nav-item:hover {
      background: var(--bg-pill);
      color: var(--text-primary);
    }

    .phase-avatar {
      width: 22px;
      height: 22px;
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 10.5px;
      font-weight: 600;
      color: #ffffff;
      flex-shrink: 0;
    }

    .av-p1 { background: #8a5a00; }
    .av-p2 { background: #006680; }
    .av-p3 { background: #005596; }
    .av-p4 { background: #7b2942; }
    .av-p5 { background: #2d4a77; }

    .phase-nav-label {
      flex: 1;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    /* Recent Sessions List */
    .session-list {
      flex: 1;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 2px;
      padding-right: 2px;
    }

    .session-item {
      padding: 8px 12px;
      border-radius: 999px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      color: var(--text-secondary);
      font-size: 13px;
      transition: background 0.12s ease, color 0.12s ease;
    }

    .session-item:hover {
      background: var(--bg-pill);
      color: var(--text-primary);
    }

    .session-item.active {
      background: var(--bg-pill);
      color: var(--text-primary);
      font-weight: 500;
    }

    .session-title {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      flex: 1;
    }

    .session-delete-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 14px;
      cursor: pointer;
      padding: 0 4px;
      opacity: 0;
      transition: opacity 0.12s ease;
    }

    .session-item:hover .session-delete-btn {
      opacity: 0.75;
    }

    .session-delete-btn:hover {
      opacity: 1 !important;
      color: var(--danger);
    }

    /* Bottom Connection Info Card (#2c2c2c) */
    .sidebar-info-card {
      background: var(--bg-card);
      border-radius: 14px;
      padding: 12px 14px;
      font-size: 12px;
      line-height: 1.45;
      color: var(--text-secondary);
      cursor: pointer;
      transition: background 0.15s ease;
    }

    .sidebar-info-card:hover {
      background: #333333;
    }

    .sidebar-info-card strong {
      display: block;
      color: var(--text-primary);
      font-size: 12.5px;
      margin-bottom: 3px;
    }

    .sidebar-bottom-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 6px 8px 2px;
      color: var(--text-secondary);
      font-size: 12.5px;
    }

    .icon-btn {
      background: transparent;
      border: none;
      color: var(--text-secondary);
      cursor: pointer;
      padding: 6px;
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      text-decoration: none;
      transition: background 0.12s ease, color 0.12s ease;
    }

    .icon-btn:hover {
      background: var(--bg-pill);
      color: var(--text-primary);
    }

    /* Main Canvas (#131415 + Subtle Deep Navy Radial Glow #141c3b) */
    .main-canvas {
      flex: 1;
      display: flex;
      flex-direction: column;
      background-color: var(--bg-canvas);
      background-image: radial-gradient(
        ellipse 66% 52% at 50% 56%,
        #141c3b 0%,
        #131b35 28%,
        #141828 52%,
        #131415 80%
      );
      height: 100vh;
      overflow: hidden;
      position: relative;
    }

    .topbar {
      height: 54px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 24px;
      flex-shrink: 0;
    }

    .topbar-title {
      font-size: 14px;
      font-weight: 500;
      color: var(--text-secondary);
      cursor: pointer;
      transition: color 0.15s ease;
    }

    .topbar-title:hover {
      color: var(--text-primary);
    }

    .top-pill {
      font-size: 12px;
      color: var(--text-secondary);
      background: var(--bg-banner);
      border: 1px solid var(--border-subtle);
      padding: 5px 12px;
      border-radius: 999px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      text-decoration: none;
      transition: background 0.15s ease, color 0.15s ease;
    }

    .top-pill:hover {
      background: var(--bg-pill);
      color: var(--text-primary);
    }

    .status-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--green);
      display: inline-block;
    }

    .chat-scroll {
      flex: 1;
      overflow-y: auto;
      padding: 16px 28px 28px;
      display: flex;
      flex-direction: column;
      gap: 22px;
    }

    /* Centered Welcome Hero ("Vamos trabalhar!" layout) */
    .welcome-container {
      max-width: 720px;
      margin: auto;
      width: 100%;
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
      gap: 22px;
      padding: 20px 0;
    }

    .welcome-title {
      font-size: 32px;
      font-weight: 400;
      letter-spacing: -0.015em;
      color: var(--text-primary);
    }

    .phase-chips-row {
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      gap: 8px;
      max-width: 680px;
    }

    .phase-chip {
      background: var(--bg-composer);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      border-radius: 999px;
      padding: 7px 14px;
      font-family: inherit;
      font-size: 12.5px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: background 0.15s ease, color 0.15s ease;
    }

    .phase-chip strong {
      color: var(--gemini-link);
      font-weight: 500;
    }

    .phase-chip:hover {
      background: var(--bg-pill);
      color: var(--text-primary);
    }

    /* Chat Messages */
    .msg-row {
      max-width: 740px;
      width: 100%;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .msg-user {
      align-self: flex-end;
      background: var(--bg-pill);
      color: var(--text-primary);
      padding: 11px 16px;
      border-radius: 20px;
      max-width: 78%;
      font-size: 14px;
      line-height: 1.55;
      white-space: pre-wrap;
    }

    .msg-attachments {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      justify-content: flex-end;
    }

    .attachment-pill {
      background: var(--bg-composer);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 11.5px;
    }

    .msg-assistant-card {
      padding: 8px 0;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .msg-assistant-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }

    .assistant-label {
      font-size: 12.5px;
      font-weight: 500;
      color: var(--text-secondary);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .msg-toolbar {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .btn-minimal-action {
      padding: 4px 10px;
      border-radius: 999px;
      border: 1px solid var(--border-subtle);
      background: var(--bg-composer);
      color: var(--text-secondary);
      font-size: 11.5px;
      cursor: pointer;
      transition: background 0.12s ease, color 0.12s ease;
    }

    .btn-minimal-action:hover {
      background: var(--bg-pill);
      color: var(--text-primary);
    }

    /* Collapsible Trace Drawer */
    .trace-drawer {
      border: 1px solid var(--border-subtle);
      background: var(--bg-banner);
      border-radius: 12px;
      overflow: hidden;
    }

    .trace-drawer summary {
      padding: 7px 12px;
      font-size: 12px;
      color: var(--text-muted);
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: space-between;
      user-select: none;
    }

    .trace-list {
      padding: 8px 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      border-top: 1px solid var(--border-subtle);
      max-height: 220px;
      overflow-y: auto;
    }

    .trace-item {
      background: var(--bg-composer);
      border-radius: 8px;
      padding: 6px 9px;
    }

    .trace-item-head {
      display: flex;
      justify-content: space-between;
      color: var(--gemini-link);
      margin-bottom: 3px;
    }

    .trace-item-pre {
      color: var(--text-secondary);
      overflow-x: auto;
      font-size: 10.5px;
      max-height: 110px;
      white-space: pre-wrap;
    }

    /* Markdown Content */
    .markdown-body {
      font-size: 14px;
      line-height: 1.65;
      color: var(--text-primary);
      overflow-x: auto;
    }

    .markdown-body h1,
    .markdown-body h2,
    .markdown-body h3,
    .markdown-body h4 {
      color: var(--text-primary);
      font-weight: 500;
      margin: 16px 0 8px;
    }

    .markdown-body h1 { font-size: 19px; }
    .markdown-body h2 {
      font-size: 16px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--border-subtle);
    }
    .markdown-body h3 { font-size: 14.5px; }

    .markdown-body p { margin-bottom: 10px; }
    .markdown-body ul, .markdown-body ol { margin: 6px 0 12px 20px; }
    .markdown-body li { margin-bottom: 4px; }

    .markdown-body table {
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0;
      font-size: 12.5px;
    }

    .markdown-body th {
      background: var(--bg-composer);
      color: var(--text-primary);
      font-weight: 500;
      text-align: left;
      padding: 8px 10px;
      border: 1px solid var(--border-subtle);
    }

    .markdown-body td {
      padding: 7px 10px;
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      vertical-align: top;
    }

    .markdown-body code {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      background: var(--bg-composer);
      padding: 2px 5px;
      border-radius: 4px;
      color: var(--gemini-link);
    }

    .code-block-wrapper {
      margin: 12px 0;
      border-radius: 12px;
      overflow: hidden;
      border: 1px solid var(--border-subtle);
      background: var(--bg-banner);
    }

    .code-block-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 6px 12px;
      background: var(--bg-composer);
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
    }

    .btn-copy-code {
      background: transparent;
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 6px;
      cursor: pointer;
    }

    .markdown-body pre {
      background: var(--bg-banner);
      color: var(--text-primary);
      padding: 12px 14px;
      overflow-x: auto;
      margin: 0;
    }

    .markdown-body pre code {
      background: transparent;
      padding: 0;
      color: inherit;
    }

    /* Gemini Enterprise Rounded Composer Box (#202020, 26px radius) */
    .composer-area {
      padding: 8px 28px 18px;
      flex-shrink: 0;
    }

    .composer-box {
      max-width: 720px;
      margin: 0 auto;
      border-radius: 26px;
      background: var(--bg-composer);
      padding: 14px 18px 10px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);
      border: 1px solid rgba(255, 255, 255, 0.04);
      transition: border-color 0.15s ease;
    }

    .composer-box.drag-over,
    .composer-box:focus-within {
      border-color: rgba(138, 180, 248, 0.28);
    }

    .file-chips-row {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }

    .file-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--bg-pill);
      color: var(--text-primary);
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
    }

    .file-chip button {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 13px;
    }

    .composer-input-row {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .composer-textarea {
      flex: 1;
      border: none;
      background: transparent;
      resize: none;
      font-family: inherit;
      font-size: 14.5px;
      line-height: 1.45;
      color: var(--text-primary);
      outline: none;
      max-height: 140px;
      min-height: 24px;
    }

    .composer-textarea::placeholder {
      color: var(--text-muted);
    }

    .composer-tools-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .composer-tools-left,
    .composer-tools-right {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .tool-icon-btn {
      width: 32px;
      height: 32px;
      border-radius: 50%;
      border: none;
      background: transparent;
      color: var(--text-secondary);
      font-size: 17px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      transition: background 0.12s ease, color 0.12s ease;
    }

    .tool-icon-btn:hover {
      background: var(--bg-pill);
      color: var(--text-primary);
    }

    .model-selector-wrapper {
      position: relative;
      display: inline-flex;
      align-items: center;
    }

    .model-selector-pill {
      font-family: inherit;
      font-size: 12.5px;
      color: var(--text-secondary);
      background: transparent;
      border: 1px solid transparent;
      padding: 5px 10px;
      border-radius: 999px;
      display: inline-flex;
      align-items: center;
      gap: 5px;
      cursor: pointer;
      transition: background 0.12s ease, color 0.12s ease, border-color 0.12s ease;
    }

    .model-selector-pill:hover,
    .model-selector-pill.active {
      background: var(--bg-pill);
      color: var(--text-primary);
      border-color: var(--border-subtle);
    }

    .model-dropdown-menu {
      position: absolute;
      bottom: calc(100% + 10px);
      right: 0;
      width: 268px;
      max-height: 360px;
      overflow-y: auto;
      background: #1e1f22;
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 14px;
      padding: 6px;
      box-shadow: 0 14px 40px rgba(0, 0, 0, 0.72);
      display: none;
      flex-direction: column;
      gap: 2px;
      z-index: 90;
    }

    .model-dropdown-menu.open {
      display: flex;
    }

    .model-option-btn {
      width: 100%;
      border: none;
      background: transparent;
      color: var(--text-secondary);
      font-family: inherit;
      font-size: 13px;
      padding: 8px 11px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      cursor: pointer;
      text-align: left;
      transition: background 0.12s ease, color 0.12s ease;
    }

    .model-option-btn:hover,
    .model-option-btn.selected {
      background: rgba(255, 255, 255, 0.08);
      color: #ffffff;
    }

    .model-option-left {
      display: flex;
      align-items: center;
      gap: 6px;
      overflow: hidden;
      white-space: nowrap;
      text-overflow: ellipsis;
    }

    .model-option-tier {
      color: var(--text-muted);
      font-weight: 400;
    }

    .model-option-badge {
      font-size: 10.5px;
      color: var(--text-secondary);
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid rgba(255, 255, 255, 0.12);
      padding: 1px 6px;
      border-radius: 999px;
      display: inline-flex;
      align-items: center;
      gap: 3px;
    }

    .model-option-arrow {
      color: var(--text-muted);
      font-size: 13px;
      flex-shrink: 0;
    }

    .model-menu-note {
      padding: 8px 12px 6px;
      font-size: 11px;
      line-height: 1.45;
      color: var(--text-muted);
      border-top: 1px solid var(--border-subtle);
      margin-top: 4px;
    }

    .served-by-badge {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      margin: 2px 0 10px;
      font-size: 11.5px;
      color: var(--text-muted);
    }

    .served-by-badge .chip {
      border: 1px solid var(--border-subtle);
      border-radius: 999px;
      padding: 1px 8px;
      font-family: "Roboto Mono", ui-monospace, monospace;
      font-size: 11px;
    }

    .served-by-badge .chip.verified {
      color: #81c995;
      border-color: rgba(129, 201, 149, 0.4);
    }

    .served-by-badge .chip.legacy,
    .served-by-badge .chip.warn {
      color: #fdd663;
      border-color: rgba(253, 214, 99, 0.4);
    }

    .msg-error-card {
      border: 1px solid rgba(242, 139, 130, 0.45);
      background: rgba(242, 139, 130, 0.08);
      border-radius: 12px;
      padding: 12px 14px;
      color: #f6aea9;
      font-size: 13px;
      line-height: 1.5;
    }

    .msg-error-card code {
      color: #f28b82;
      font-family: "Roboto Mono", ui-monospace, monospace;
      margin-right: 6px;
    }

    .btn-send {
      width: 32px;
      height: 32px;
      border-radius: 50%;
      border: none;
      background: var(--bg-pill);
      color: var(--text-primary);
      font-size: 14px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      transition: background 0.15s ease;
    }

    .btn-send:hover {
      background: #383a3d;
    }

    .btn-send:disabled {
      opacity: 0.35;
      cursor: not-allowed;
    }

    .composer-disclaimer {
      max-width: 680px;
      margin: 8px auto 0;
      text-align: center;
      font-size: 11.5px;
      color: var(--text-muted);
    }

    /* Dark Modal (#202020) */
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.72);
      backdrop-filter: blur(4px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 100;
    }

    .modal-backdrop.open {
      display: flex;
    }

    .modal-panel {
      background: var(--bg-sidebar);
      width: 560px;
      max-width: 92vw;
      border-radius: 18px;
      border: 1px solid var(--border-subtle);
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }

    .modal-header {
      padding: 14px 18px;
      border-bottom: 1px solid var(--border-subtle);
      color: var(--text-primary);
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 14px;
      font-weight: 500;
    }

    .modal-body {
      padding: 16px 18px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .conn-grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }

    .conn-field {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .conn-field label {
      font-size: 11px;
      color: var(--text-muted);
    }

    .conn-field select,
    .conn-field input,
    .gcloud-input-bar input {
      width: 100%;
      padding: 8px 11px;
      border-radius: 8px;
      border: 1px solid var(--border-subtle);
      background: var(--bg-banner);
      font-size: 12.5px;
      color: var(--text-primary);
      font-family: inherit;
      outline: none;
    }

    .gcloud-input-bar {
      display: flex;
      gap: 8px;
    }

    .gcloud-input-bar input {
      font-family: 'JetBrains Mono', monospace;
    }

    .btn-modal-primary {
      padding: 8px 14px;
      border-radius: 999px;
      border: none;
      background: var(--gemini-blue);
      color: #ffffff;
      font-size: 12.5px;
      font-weight: 500;
      cursor: pointer;
      white-space: nowrap;
    }

    .gcloud-output-console {
      background: var(--bg-canvas);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      font-family: 'JetBrains Mono', monospace;
      font-size: 11.5px;
      padding: 10px;
      border-radius: 10px;
      min-height: 110px;
      max-height: 220px;
      overflow: auto;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <!-- Left Sidebar (#202020) -->
  <aside class="sidebar">
    <div class="sidebar-brand-row">
      <div class="brand-title" onclick="goHome()" title="Return to home screen">
        <!-- Blue 4-point Gemini Star -->
        <svg class="gemini-sparkle" viewBox="0 0 24 24" fill="none">
          <path d="M12 2C12 7.52 16.48 12 22 12C16.48 12 12 16.48 12 22C12 16.48 7.52 12 2 12C7.52 12 12 7.52 12 2Z" fill="url(#geminiGrad)"/>
          <defs>
            <linearGradient id="geminiGrad" x1="2" y1="2" x2="22" y2="22" gradientUnits="userSpaceOnUse">
              <stop stop-color="#4C8DF6"/>
              <stop offset="1" stop-color="#1A73E8"/>
            </linearGradient>
          </defs>
        </svg>
        <span>Agentic PQC Workspace</span>
      </div>
    </div>

    <button class="btn-new-assessment" id="new-session-btn" onclick="createNewSession()">
      <span>✎</span>
      <span>New PQC Assessment</span>
    </button>

    <div class="search-nav-row">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;opacity:0.75;">
        <circle cx="11" cy="11" r="8"></circle>
        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
      </svg>
      <input type="text" id="session-search-input" placeholder="Search history..." oninput="renderSessionList()" />
    </div>

    <div class="sidebar-section-header">
      <span>Phases</span>
      <span>›</span>
    </div>
    <div class="phase-nav-list">
      <button class="phase-nav-item" onclick="runLabPrompt(0)">
        <span class="phase-avatar av-p1">P1</span>
        <span class="phase-nav-label">Org Discovery</span>
      </button>
      <button class="phase-nav-item" onclick="runLabPrompt(1)">
        <span class="phase-avatar av-p2">P2</span>
        <span class="phase-nav-label">Org Policies</span>
      </button>
      <button class="phase-nav-item" onclick="runLabPrompt(2)">
        <span class="phase-avatar av-p3">P3</span>
        <span class="phase-nav-label">Hybrid TLS 1.3</span>
      </button>
      <button class="phase-nav-item" onclick="runLabPrompt(3)">
        <span class="phase-avatar av-p4">P4</span>
        <span class="phase-nav-label">BYOK &amp; CBOM</span>
      </button>
      <button class="phase-nav-item" onclick="runLabPrompt(4)">
        <span class="phase-avatar av-p5">P5</span>
        <span class="phase-nav-label">Terraform BOM</span>
      </button>
    </div>

    <div class="sidebar-section-header">
      <span>Recent</span>
      <span id="session-count-badge">0</span>
    </div>
    <div class="session-list" id="session-list"></div>

    <!-- Bottom Connection Card (#2c2c2c) -->
    <div class="sidebar-info-card" onclick="openGcloudModal()">
      <strong>GCP / gcloud Connection</strong>
      <span>Org 31564119954 • <span id="conn-status-dot" style="color:var(--gemini-link);">ADC</span></span>
    </div>

    <div class="sidebar-bottom-bar">
      <span>Google Cloud Consulting</span>
      <div style="display:flex;gap:4px;">
        <a class="icon-btn" href="/dev-ui/?app=pqc_agent" target="_blank" rel="noopener" title="/dev-ui/">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="16 18 22 12 16 6"></polyline>
            <polyline points="8 6 2 12 8 18"></polyline>
          </svg>
        </a>
        <button class="icon-btn" onclick="openGcloudModal()" title="Settings &amp; gcloud">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="3"></circle>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
          </svg>
        </button>
      </div>
    </div>
  </aside>

  <!-- Main Canvas (#131415 + Radial Deep Blue Glow) -->
  <main class="main-canvas">
    <header class="topbar">
      <div class="topbar-title" onclick="goHome()" title="Return to home screen">Agentic PQC Workspace</div>
      <div style="display:flex;align-items:center;gap:8px;">
        <button class="top-pill" id="header-conn-badge" onclick="openGcloudModal()">
          <span class="status-dot"></span>
          <span id="header-conn-text">Org 31564119954 • ADC</span>
        </button>
      </div>
    </header>

    <div class="chat-scroll" id="chat-scroll">
      <!-- Centered Welcome Screen -->
      <div class="welcome-container" id="welcome-screen">
        <h1 class="welcome-title">Agentic Post-Quantum Cryptography</h1>

        <div class="phase-chips-row">
          <button class="phase-chip" onclick="runLabPrompt(0)">
            <strong>P1</strong> Org Discovery &amp; Mosca
          </button>
          <button class="phase-chip" onclick="runLabPrompt(1)">
            <strong>P2</strong> Preventive Org Policies
          </button>
          <button class="phase-chip" onclick="runLabPrompt(2)">
            <strong>P3</strong> Hybrid TLS 1.3 &amp; JWT
          </button>
          <button class="phase-chip" onclick="runLabPrompt(3)">
            <strong>P4</strong> BYOK &amp; CycloneDX CBOM
          </button>
          <button class="phase-chip" onclick="runLabPrompt(4)">
            <strong>P5</strong> Target Terraform BOM
          </button>
        </div>
      </div>

      <div id="messages-container" style="display: flex; flex-direction: column; gap: 20px;"></div>
    </div>

    <!-- Gemini Enterprise Composer Box (#202020) -->
    <div class="composer-area">
      <div class="composer-box" id="composer-dropzone">
        <div class="file-chips-row" id="file-chips-row"></div>
        <div class="composer-input-row">
          <textarea
            id="chat-input"
            class="composer-textarea"
            rows="1"
            placeholder="Ask Agentic PQC Workspace..."
            onkeydown="handleComposerKeydown(event)"
          ></textarea>
        </div>
        <div class="composer-tools-row">
          <div class="composer-tools-left">
            <input
              type="file"
              id="file-upload-input"
              multiple
              accept=".pdf,.docx,.txt,.md,.csv,.json,.png,.jpg,.jpeg,.pem,.crt,.cer,.yaml,.yml"
              style="display: none;"
              onchange="handleFileSelect(event)"
            />
            <button class="tool-icon-btn" type="button" onclick="document.getElementById('file-upload-input').click()" title="Attach file">
              ＋
            </button>
            <button class="tool-icon-btn" type="button" onclick="openGcloudModal()" title="GCP / gcloud Connection">
              ⊶
            </button>
          </div>
          <div class="composer-tools-right">
            <div class="model-selector-wrapper" id="model-selector-wrapper">
              <button
                type="button"
                class="model-selector-pill"
                id="model-selector-btn"
                onclick="toggleModelMenu(event)"
                title="Select AI Model"
              >
                <span id="selected-model-label">Verifying models...</span>
                <span>▾</span>
              </button>
              <div class="model-dropdown-menu" id="model-dropdown-menu"></div>
            </div>
            <button class="btn-send" id="send-btn" type="button" onclick="sendChatMessage()" title="Send">
              ↑
            </button>
          </div>
        </div>
      </div>
      <div class="composer-disclaimer">
        Generative AI may display inaccurate info. Always verify PQC migration plans before production rollout.
      </div>
    </div>
  </main>

  <!-- Unified Connection & gcloud CLI Modal -->
  <div class="modal-backdrop" id="gcloud-modal">
    <div class="modal-panel">
      <div class="modal-header">
        <span>GCP / gcloud Connection &amp; CLI</span>
        <button onclick="closeGcloudModal()" style="background:transparent;border:none;color:var(--text-secondary);font-size:16px;cursor:pointer;">✕</button>
      </div>
      <div class="modal-body">
        <div class="conn-grid-2">
          <div class="conn-field">
            <label for="conn-mode-select">Auth Mode</label>
            <select id="conn-mode-select" onchange="toggleConnectionModeFields()">
              <option value="adc">Service Account (Default ADC)</option>
              <option value="impersonation">Service Account Impersonation</option>
              <option value="access_token">User gcloud Access Token</option>
            </select>
          </div>
          <div class="conn-field">
            <label for="conn-org-input">Organization ID</label>
            <input type="text" id="conn-org-input" value="31564119954" />
          </div>
        </div>

        <div class="conn-field">
          <label for="conn-proj-input">Project ID</label>
          <input type="text" id="conn-proj-input" value="pqc-inventory-agent-cd06" />
        </div>

        <div class="conn-field" id="conn-sa-group" style="display: none;">
          <label for="conn-sa-input">Impersonated SA Email</label>
          <input type="text" id="conn-sa-input" placeholder="pqc-reader@customer.iam.gserviceaccount.com" />
        </div>

        <div class="conn-field" id="conn-token-group" style="display: none;">
          <label for="conn-token-input">Access Token</label>
          <input type="password" id="conn-token-input" placeholder="gcloud auth print-access-token" />
        </div>

        <div style="display:flex;justify-content:flex-end;">
          <button class="btn-modal-primary" onclick="saveConnectionConfig()">Save Connection</button>
        </div>

        <hr style="border:none;border-top:1px solid var(--border-subtle);" />

        <div class="conn-field">
          <label for="gcloud-cmd-input">Read-Only gcloud CLI</label>
          <div class="gcloud-input-bar">
            <input type="text" id="gcloud-cmd-input" value="gcloud kms keys list --location=global --project=pqc-inventory-agent-cd06" />
            <button class="btn-modal-primary" onclick="runDirectGcloudCommand()">Run</button>
          </div>
        </div>
        <div class="gcloud-output-console" id="gcloud-output-console"># Ready.</div>
      </div>
    </div>
  </div>

  <script>
    const PHASE_TITLES = [
      "P1 • Org Discovery",
      "P2 • Org Policies",
      "P3 • Hybrid TLS 1.3",
      "P4 • BYOK & CBOM",
      "P5 • Terraform BOM"
    ];

    const LAB_PROMPTS = [
      "Run a complete post-quantum cryptography readiness assessment for scope '{ORG}'. Use the discovery, correlation and quantum risk specialists, then the remediation architect. Deliver the consulting assessment with evidence: inventory facts, key-to-workload correlations with evidence levels, the scorecard with numerators and denominators, the Mosca analysis (say whether the parameters are calibrated or default), prioritized risks and a phased plan.",
      "Evaluate the cryptographic governance posture of scope '{ORG}': keys with quantum-vulnerable or below-target algorithms, symmetric keys without rotation and protection levels. Then have the remediation architect propose preventive Organization Policy custom constraints and rotation runbooks for the exact keys found.",
      "Assess transport-layer exposure in scope '{ORG}': SSL policies and HTTPS/SSL target proxies (effective policy and minimum TLS version) and the signing keys used for tokens. Explain store-now-decrypt-later exposure with evidence, and propose TLS 1.3 policy changes plus the gateway, header-size and verifier impact of moving signing keys to ML-DSA, using the sizes reported by the tools.",
      "Inspect Cloud KMS import jobs in scope '{ORG}' for classical RSA-OAEP wrapping, correlate keys to workloads, and have the report writer export a CycloneDX v1.6 CBOM that includes only validated correlations. Propose the migration of import jobs to post-quantum HPKE wrapping.",
      "Design the target Google Cloud architecture for the PQC migration of scope '{ORG}' grounded in the discovered resources: Cloud KMS and Cloud HSM post-quantum keys, Tink HPKE for applications, VPC Service Controls, Certificate Authority Service, Binary Authorization and Security Command Center. Provide Terraform and gcloud for the specific resources found and mark every new resource name as proposed."
    ];

    let MODEL_OPTIONS = [];
    let MODEL_CATALOG_META = { verification: null, unavailable: [], project: null, default_model: null };

    let currentUserId = localStorage.getItem("pqc_user_id") || "sec-architect";
    let currentSessionId = localStorage.getItem("pqc_active_session_id") || null;
    let selectedModelId = localStorage.getItem("pqc_selected_model_id") || "";
    let allSessions = [];
    let pendingFiles = [];
    let assistantResponsesStore = {};

    async function loadModelCatalog(forceRefresh = false) {
      try {
        const res = await fetch(`/api/models${forceRefresh ? "?refresh=true" : ""}`);
        const data = await res.json();
        MODEL_OPTIONS = data.models || [];
        MODEL_CATALOG_META = {
          verification: data.verification || null,
          unavailable: data.unavailable_candidates || [],
          project: data.project || null,
          default_model: data.default_model || null,
        };
        const ids = MODEL_OPTIONS.map((m) => m.id);
        if (!ids.includes(selectedModelId)) {
          selectedModelId = data.default_model || ids[0] || "";
          if (selectedModelId) localStorage.setItem("pqc_selected_model_id", selectedModelId);
        }
        const status = data.verification ? data.verification.status : "";
        if (MODEL_OPTIONS.length === 0 && status !== "COMPLETE") {
          setTimeout(() => loadModelCatalog(), 4000);
        }
      } catch (err) {
        MODEL_OPTIONS = [];
      }
      renderModelDropdown();
    }

    function getModelDisplayLabel(modelId) {
      const found = MODEL_OPTIONS.find((m) => m.id === modelId);
      if (!found) return MODEL_OPTIONS.length ? "Select a model" : "Verifying models...";
      return found.tier ? `${found.label} · ${found.tier}` : found.label;
    }

    function renderModelDropdown() {
      const menuEl = document.getElementById("model-dropdown-menu");
      const btnLabelEl = document.getElementById("selected-model-label");
      if (btnLabelEl) {
        btnLabelEl.textContent = getModelDisplayLabel(selectedModelId);
      }
      if (!menuEl) return;
      menuEl.innerHTML = "";

      if (MODEL_OPTIONS.length === 0) {
        const pending = document.createElement("div");
        pending.className = "model-menu-note";
        pending.textContent = "Verifying which Gemini models answer on Vertex AI in this project...";
        menuEl.appendChild(pending);
        return;
      }

      MODEL_OPTIONS.forEach((opt) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "model-option-btn" + (opt.id === selectedModelId ? " selected" : "");
        btn.onclick = (ev) => {
          ev.stopPropagation();
          selectModel(opt.id);
        };
        const tierHtml = opt.tier ? ` <span class="model-option-tier">${escapeHtml(opt.tier)}</span>` : "";
        btn.innerHTML = `
          <span class="model-option-left">
            <span>${escapeHtml(opt.label)}${tierHtml}</span>
          </span>
          <span class="model-option-badge" title="Vertex AI model ID: ${escapeHtml(opt.model)}">verified</span>
        `;
        menuEl.appendChild(btn);
      });

      const note = document.createElement("div");
      note.className = "model-menu-note";
      const unavailableCount = (MODEL_CATALOG_META.unavailable || []).length;
      const projectTxt = MODEL_CATALOG_META.project ? ` (${MODEL_CATALOG_META.project})` : "";
      note.textContent =
        `Gemini only. Each model listed answered a live verification request on Vertex AI${projectTxt}.` +
        (unavailableCount ? ` ${unavailableCount} candidate model(s) unavailable in this project are hidden.` : "");
      menuEl.appendChild(note);
    }

    function toggleModelMenu(event) {
      if (event) event.stopPropagation();
      const menuEl = document.getElementById("model-dropdown-menu");
      const btnEl = document.getElementById("model-selector-btn");
      if (!menuEl) return;
      const isOpen = menuEl.classList.toggle("open");
      if (btnEl) btnEl.classList.toggle("active", isOpen);
    }

    function selectModel(modelId) {
      selectedModelId = modelId;
      localStorage.setItem("pqc_selected_model_id", modelId);
      renderModelDropdown();
      const menuEl = document.getElementById("model-dropdown-menu");
      const btnEl = document.getElementById("model-selector-btn");
      if (menuEl) menuEl.classList.remove("open");
      if (btnEl) btnEl.classList.remove("active");
    }

    document.addEventListener("click", (ev) => {
      const wrapper = document.getElementById("model-selector-wrapper");
      const menuEl = document.getElementById("model-dropdown-menu");
      const btnEl = document.getElementById("model-selector-btn");
      if (wrapper && !wrapper.contains(ev.target)) {
        if (menuEl) menuEl.classList.remove("open");
        if (btnEl) btnEl.classList.remove("active");
      }
    });

    function renderMarkdownSafe(mdText) {
      if (window.marked) {
        const rawHtml = marked.parse(mdText || "");
        return window.DOMPurify ? DOMPurify.sanitize(rawHtml) : rawHtml;
      }
      return "<pre>" + escapeHtml(mdText || "") + "</pre>";
    }

    function escapeHtml(str) {
      return String(str || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }

    function enhanceCodeBlocks(containerEl) {
      const pres = containerEl.querySelectorAll("pre");
      pres.forEach((pre) => {
        if (pre.parentElement && pre.parentElement.classList.contains("code-block-wrapper")) return;
        const codeEl = pre.querySelector("code");
        const langClass = codeEl ? (codeEl.className || "") : "";
        const lang = langClass.replace("language-", "") || "code";
        const wrapper = document.createElement("div");
        wrapper.className = "code-block-wrapper";

        const bar = document.createElement("div");
        bar.className = "code-block-bar";
        bar.innerHTML = `<span>${escapeHtml(lang.toUpperCase())}</span>`;

        const copyBtn = document.createElement("button");
        copyBtn.className = "btn-copy-code";
        copyBtn.textContent = "Copy";
        copyBtn.onclick = () => {
          navigator.clipboard.writeText(pre.innerText || "");
          copyBtn.textContent = "Copied";
          setTimeout(() => { copyBtn.textContent = "Copy"; }, 1500);
        };
        bar.appendChild(copyBtn);

        pre.parentNode.insertBefore(wrapper, pre);
        wrapper.appendChild(bar);
        wrapper.appendChild(pre);
      });
    }

    function toggleConnectionModeFields() {
      const mode = document.getElementById("conn-mode-select").value;
      document.getElementById("conn-sa-group").style.display = mode === "impersonation" ? "flex" : "none";
      document.getElementById("conn-token-group").style.display = mode === "access_token" ? "flex" : "none";
    }

    async function loadConnectionConfig() {
      try {
        const res = await fetch("/api/connection");
        if (!res.ok) return;
        const cfg = await res.json();
        document.getElementById("conn-mode-select").value = cfg.mode || "adc";
        document.getElementById("conn-org-input").value = cfg.organization_id || "31564119954";
        document.getElementById("conn-proj-input").value = cfg.project_id || "pqc-inventory-agent-cd06";
        document.getElementById("conn-sa-input").value = cfg.impersonated_service_account || "";
        toggleConnectionModeFields();
        updateHeaderConnectionBadge(cfg);
      } catch (e) {
        console.warn("Connection status warning:", e);
      }
    }

    function updateHeaderConnectionBadge(cfg) {
      const modeShort = cfg.mode === "impersonation" ? "Impersonated SA" : (cfg.mode === "access_token" ? "Token" : "ADC");
      document.getElementById("header-conn-text").textContent = `Org ${cfg.organization_id} • ${modeShort}`;
      document.getElementById("conn-status-dot").textContent = modeShort;
    }

    async function saveConnectionConfig() {
      const payload = {
        mode: document.getElementById("conn-mode-select").value,
        organization_id: document.getElementById("conn-org-input").value.trim(),
        project_id: document.getElementById("conn-proj-input").value.trim(),
        impersonated_service_account: document.getElementById("conn-sa-input").value.trim(),
        access_token: document.getElementById("conn-token-input").value.trim() || undefined,
      };
      const res = await fetch("/api/connection", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const updated = await res.json();
        updateHeaderConnectionBadge(updated);
      }
    }

    async function fetchSessions() {
      try {
        const res = await fetch(`/api/sessions?user_id=${encodeURIComponent(currentUserId)}`);
        if (!res.ok) return;
        const data = await res.json();
        allSessions = data.sessions || [];
        document.getElementById("session-count-badge").textContent = String(allSessions.length);
        renderSessionList();
      } catch (e) {
        console.warn("Session list error:", e);
      }
    }

    function goHome() {
      currentSessionId = null;
      localStorage.removeItem("pqc_active_session_id");
      document.getElementById("messages-container").innerHTML = "";
      document.getElementById("welcome-screen").style.display = "flex";
      renderSessionList();
    }

    function renderSessionList() {
      const listEl = document.getElementById("session-list");
      const filter = (document.getElementById("session-search-input").value || "").toLowerCase().trim();
      listEl.innerHTML = "";
      const filtered = allSessions.filter((s) => {
        if (!filter) return true;
        return (s.title || "").toLowerCase().includes(filter) || (s.session_id || "").toLowerCase().includes(filter);
      });

      if (filtered.length === 0) {
        listEl.innerHTML = `<div style="padding:10px 14px;font-size:12px;color:var(--text-muted);">No recent conversations</div>`;
        return;
      }

      filtered.forEach((sess) => {
        const item = document.createElement("div");
        item.className = "session-item" + (sess.session_id === currentSessionId ? " active" : "");
        item.onclick = () => loadSessionHistory(sess.session_id);

        item.innerHTML = `<div class="session-title">${escapeHtml(sess.title || "PQC Assessment")}</div>`;

        const delBtn = document.createElement("button");
        delBtn.className = "session-delete-btn";
        delBtn.title = "Delete";
        delBtn.textContent = "×";
        delBtn.onclick = async (ev) => {
          ev.stopPropagation();
          await deleteSessionById(sess.session_id);
        };
        item.appendChild(delBtn);
        listEl.appendChild(item);
      });
    }

    async function createNewSession(customTitle) {
      const orgId = document.getElementById("conn-org-input").value.trim() || "31564119954";
      const sessionTitle = (typeof customTitle === "string" && customTitle.trim()) ? customTitle.trim() : "New PQC Assessment";
      const res = await fetch("/api/sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_id: currentUserId,
          title: sessionTitle,
          scope: `organizations/${orgId.replace("organizations/", "")}`,
        }),
      });
      if (res.ok) {
        const created = await res.json();
        currentSessionId = created.session_id;
        localStorage.setItem("pqc_active_session_id", currentSessionId);
        document.getElementById("messages-container").innerHTML = "";
        document.getElementById("welcome-screen").style.display = "flex";
        await fetchSessions();
      }
    }

    async function loadSessionHistory(sessionId) {
      currentSessionId = sessionId;
      localStorage.setItem("pqc_active_session_id", sessionId);
      renderSessionList();
      const res = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}?user_id=${encodeURIComponent(currentUserId)}`);
      if (!res.ok) return;
      const data = await res.json();
      const msgs = data.messages || [];
      const container = document.getElementById("messages-container");
      container.innerHTML = "";

      if (msgs.length === 0) {
        document.getElementById("welcome-screen").style.display = "flex";
      } else {
        document.getElementById("welcome-screen").style.display = "none";
        msgs.forEach((m) => {
          if (m.role === "user") {
            appendUserMessageUI(m.content, m.attachments || []);
          } else {
            appendAssistantMessageUI(m.content, m.tool_calls || [], m.model_label, m.served_by || null, m.error || null, Boolean(m.legacy_template_response));
          }
        });
      }
      scrollToBottom();
    }

    async function deleteSessionById(sessionId) {
      const res = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}?user_id=${encodeURIComponent(currentUserId)}`, {
        method: "DELETE",
      });
      if (res.ok) {
        if (currentSessionId === sessionId) {
          currentSessionId = null;
          localStorage.removeItem("pqc_active_session_id");
          document.getElementById("messages-container").innerHTML = "";
          document.getElementById("welcome-screen").style.display = "flex";
        }
        await fetchSessions();
      }
    }

    function handleFileSelect(event) {
      const files = Array.from(event.target.files || []);
      files.forEach((f) => pendingFiles.push(f));
      event.target.value = "";
      renderFileChips();
    }

    function renderFileChips() {
      const row = document.getElementById("file-chips-row");
      row.innerHTML = "";
      pendingFiles.forEach((f, idx) => {
        const kb = Math.max(1, Math.round(f.size / 1024));
        const chip = document.createElement("div");
        chip.className = "file-chip";
        chip.innerHTML = `<span>${escapeHtml(f.name)} (${kb} KB)</span>`;
        const rmBtn = document.createElement("button");
        rmBtn.textContent = "×";
        rmBtn.onclick = () => {
          pendingFiles.splice(idx, 1);
          renderFileChips();
        };
        chip.appendChild(rmBtn);
        row.appendChild(chip);
      });
    }

    function appendUserMessageUI(text, attachments = []) {
      const container = document.getElementById("messages-container");
      const row = document.createElement("div");
      row.className = "msg-row";
      let attachHtml = "";
      if (attachments && attachments.length > 0) {
        attachHtml = `<div class="msg-attachments">` +
          attachments.map((a) => `<span class="attachment-pill">${escapeHtml(a.filename || a.name || a)}</span>`).join("") +
          `</div>`;
      }
      row.innerHTML = `${attachHtml}<div class="msg-user">${escapeHtml(text)}</div>`;
      container.appendChild(row);
    }

    function formatTokens(n) {
      return typeof n === "number" ? n.toLocaleString("en-US") : "0";
    }

    function buildServedByHtml(servedBy, legacyTemplate) {
      if (legacyTemplate) {
        return `<div class="served-by-badge"><span class="chip legacy">Legacy template response from the previous version (not generated by a model)</span></div>`;
      }
      if (!servedBy || !(servedBy.models_used || []).length) {
        return "";
      }
      const models = servedBy.models_used.map((m) => `<span class="chip verified">${escapeHtml(m)}</span>`).join("");
      const agents = (servedBy.agents_involved || []).filter((a) => a && a !== "user");
      const agentsTxt = agents.length ? ` · agents: ${escapeHtml(agents.join(", "))}` : "";
      const calls = servedBy.llm_call_count || 0;
      return `
        <div class="served-by-badge" title="Model version and token usage reported by Vertex AI for this answer">
          <span>Answered by</span>${models}
          <span>· ${calls} LLM call${calls === 1 ? "" : "s"} · ${formatTokens(servedBy.prompt_tokens)} in / ${formatTokens(servedBy.output_tokens)} out / ${formatTokens(servedBy.thinking_tokens)} thinking tokens${agentsTxt}</span>
        </div>`;
    }

    function appendAssistantMessageUI(markdownText, toolCalls = [], modelLabel = "", servedBy = null, errorInfo = null, legacyTemplate = false) {
      const container = document.getElementById("messages-container");
      const msgId = "msg-" + Math.random().toString(36).slice(2, 10);
      assistantResponsesStore[msgId] = markdownText || "";

      const row = document.createElement("div");
      row.className = "msg-row";

      let traceDrawerHtml = "";
      if (toolCalls && toolCalls.length > 0) {
        const itemsHtml = toolCalls.map((tc) => {
          const argsStr = typeof tc.args === "string" ? tc.args : JSON.stringify(tc.args || {});
          const outStr = typeof tc.output_preview === "string" ? tc.output_preview : JSON.stringify(tc.output_preview || "");
          const kindLabel = tc.kind === "specialist_agent" ? "Specialist agent" : "Tool";
          return `
            <div class="trace-item">
              <div class="trace-item-head">
                <span>${escapeHtml(kindLabel)}: ${escapeHtml(tc.name || "tool")}</span>
                <span>${escapeHtml(tc.status || "OK")}</span>
              </div>
              <div style="color:var(--text-muted);margin-bottom:3px;">${escapeHtml(argsStr)}</div>
              ${outStr ? `<div class="trace-item-pre">${escapeHtml(outStr.slice(0, 500))}</div>` : ""}
            </div>
          `;
        }).join("");

        traceDrawerHtml = `
          <details class="trace-drawer">
            <summary>
              <span>Agent, Tool &amp; gcloud Execution Trace (${toolCalls.length})</span>
              <span>▾</span>
            </summary>
            <div class="trace-list">${itemsHtml}</div>
          </details>
        `;
      }

      const activeBadge = modelLabel || getModelDisplayLabel(selectedModelId);
      const toolbarHtml = errorInfo ? "" : `
            <div class="msg-toolbar">
              <button class="btn-minimal-action" onclick="downloadMarkdownReport('${msgId}')">
                Download Report (.md)
              </button>
              <button class="btn-minimal-action" onclick="copyFullResponse('${msgId}', this)">
                Copy
              </button>
            </div>`;
      const bodyHtml = errorInfo
        ? `<div class="msg-error-card"><strong>The model did not return an answer.</strong> Nothing was generated or substituted for this turn.<br/><code>${escapeHtml(String(errorInfo.code || "ERROR"))}</code>${escapeHtml(String(errorInfo.message || ""))}</div>`
        : `<div class="markdown-body" id="md-${msgId}">${renderMarkdownSafe(markdownText)}</div>`;

      row.innerHTML = `
        <div class="msg-assistant-card">
          <div class="msg-assistant-bar">
            <div class="assistant-label">
              <span style="color:var(--gemini-blue);">✦</span>
              <span>Agentic PQC Workspace</span>
              <span style="color:var(--text-muted);font-size:11.5px;font-weight:400;">• ${escapeHtml(activeBadge)}</span>
            </div>
            ${toolbarHtml}
          </div>
          ${buildServedByHtml(servedBy, legacyTemplate)}
          ${traceDrawerHtml}
          ${bodyHtml}
        </div>
      `;
      container.appendChild(row);
      const mdEl = document.getElementById(`md-${msgId}`);
      if (mdEl) enhanceCodeBlocks(mdEl);
    }

    function downloadMarkdownReport(msgId) {
      const md = assistantResponsesStore[msgId] || "";
      const orgId = document.getElementById("conn-org-input").value.trim() || "31564119954";
      const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `PQC_Assessment_${orgId}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    function copyFullResponse(msgId, btnEl) {
      const md = assistantResponsesStore[msgId] || "";
      navigator.clipboard.writeText(md);
      const orig = btnEl.textContent;
      btnEl.textContent = "Copied";
      setTimeout(() => { btnEl.textContent = orig; }, 1500);
    }

    async function runLabPrompt(index) {
      const template = LAB_PROMPTS[index];
      if (!template) return;
      const orgId = (document.getElementById("conn-org-input").value.trim() || "31564119954").replace("organizations/", "");
      const promptText = template.split("{ORG}").join(`organizations/${orgId}`);
      await createNewSession(PHASE_TITLES[index] || "New PQC Assessment");
      document.getElementById("chat-input").value = promptText;
      await sendChatMessage({ isPhaseScan: true });
    }

    function handleComposerKeydown(event) {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        sendChatMessage();
      }
    }

    async function sendChatMessage(options = {}) {
      const inputEl = document.getElementById("chat-input");
      const messageText = inputEl.value.trim();
      if (!messageText && pendingFiles.length === 0) return;

      const sendBtn = document.getElementById("send-btn");
      sendBtn.disabled = true;
      document.getElementById("welcome-screen").style.display = "none";

      const attachedMeta = pendingFiles.map((f) => ({ filename: f.name, size: f.size }));
      appendUserMessageUI(messageText || "(Attached file)", attachedMeta);

      const formData = new FormData();
      formData.append("message", messageText || "Read the attached file(s), explain what they contain and how they affect our PQC assessment.");
      formData.append("user_id", currentUserId);
      formData.append("model_id", selectedModelId);
      if (currentSessionId) {
        formData.append("session_id", currentSessionId);
      }
      const orgId = document.getElementById("conn-org-input").value.trim() || "31564119954";
      formData.append("scope", `organizations/${orgId.replace("organizations/", "")}`);
      formData.append("connection_mode", document.getElementById("conn-mode-select").value);
      formData.append("impersonated_sa", document.getElementById("conn-sa-input").value.trim());
      const tok = document.getElementById("conn-token-input").value.trim();
      if (tok) formData.append("access_token", tok);

      const hasFiles = pendingFiles.length > 0;
      pendingFiles.forEach((f) => formData.append("files", f));
      inputEl.value = "";
      pendingFiles = [];
      renderFileChips();

      const isScanAction = Boolean(options.isPhaseScan || hasFiles);
      const statusLabel = isScanAction
        ? `✦ Running specialist agents on ${getModelDisplayLabel(selectedModelId)}...`
        : `✦ Thinking (${getModelDisplayLabel(selectedModelId)})...`;

      const container = document.getElementById("messages-container");
      const loadingRow = document.createElement("div");
      loadingRow.className = "msg-row";
      loadingRow.innerHTML = `<div style="color:var(--text-muted);font-size:13px;padding:6px 0;">${escapeHtml(statusLabel)}</div>`;
      container.appendChild(loadingRow);
      scrollToBottom();

      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          body: formData,
        });
        loadingRow.remove();
        let data = null;
        try {
          data = await res.json();
        } catch (parseErr) {
          data = null;
        }
        if (data && data.session_id) {
          currentSessionId = data.session_id;
          localStorage.setItem("pqc_active_session_id", currentSessionId);
        }
        if (!res.ok || !data || data.status !== "OK") {
          const errorInfo = (data && data.error) || { code: `HTTP ${res.status}`, message: "Unexpected server response." };
          appendAssistantMessageUI(
            "",
            (data && (data.tool_calls || data.tool_traces)) || [],
            (data && data.model_label) || getModelDisplayLabel(selectedModelId),
            (data && data.served_by) || null,
            errorInfo
          );
          if (data && data.status === "MODEL_NOT_AVAILABLE") {
            await loadModelCatalog(true);
          }
        } else {
          appendAssistantMessageUI(
            data.response || "",
            data.tool_calls || data.tool_traces || [],
            data.model_label || getModelDisplayLabel(selectedModelId),
            data.served_by || null,
            null
          );
        }
        await fetchSessions();
      } catch (err) {
        loadingRow.remove();
        appendAssistantMessageUI("", [], getModelDisplayLabel(selectedModelId), null, { code: "NETWORK_ERROR", message: String(err) });
      } finally {
        sendBtn.disabled = false;
        scrollToBottom();
      }
    }

    function scrollToBottom() {
      const sc = document.getElementById("chat-scroll");
      sc.scrollTop = sc.scrollHeight;
    }

    function openGcloudModal() {
      document.getElementById("gcloud-modal").classList.add("open");
    }

    function closeGcloudModal() {
      document.getElementById("gcloud-modal").classList.remove("open");
    }

    async function runDirectGcloudCommand() {
      const cmd = document.getElementById("gcloud-cmd-input").value.trim();
      const outEl = document.getElementById("gcloud-output-console");
      if (!cmd) return;
      outEl.textContent = `$ ${cmd}\nRunning...`;
      try {
        const res = await fetch("/api/gcloud", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ command: cmd }),
        });
        const data = await res.json();
        if (data.status === "SUCCESS") {
          outEl.textContent = `$ ${cmd}\n\n${data.stdout || "(no stdout)"}${data.stderr ? "\n" + data.stderr : ""}`;
        } else {
          outEl.textContent = `$ ${cmd}\n[${data.status}]\n${data.error || data.stderr || JSON.stringify(data, null, 2)}`;
        }
      } catch (e) {
        outEl.textContent = `Error: ${e}`;
      }
    }

    const dropzone = document.getElementById("composer-dropzone");
    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("drag-over");
    });
    dropzone.addEventListener("dragleave", () => {
      dropzone.classList.remove("drag-over");
    });
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("drag-over");
      const files = Array.from(e.dataTransfer.files || []);
      files.forEach((f) => pendingFiles.push(f));
      renderFileChips();
    });

    window.addEventListener("DOMContentLoaded", async () => {
      const linkedSession = new URLSearchParams(window.location.search).get("session");
      if (linkedSession) {
        currentSessionId = linkedSession;
      }
      renderModelDropdown();
      await loadModelCatalog();
      await loadConnectionConfig();
      await fetchSessions();
      if (currentSessionId) {
        await loadSessionHistory(currentSessionId);
      }
    });
  </script>
</body>
</html>
"""
