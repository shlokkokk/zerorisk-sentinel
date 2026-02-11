# ZeroRisk Sentinel - Frontend

The web interface for ZeroRisk Sentinel, a hybrid cybersecurity analysis platform. Built with vanilla JavaScript and a cyberpunk aesthetic, this frontend provides file scanning, URL analysis, and comprehensive security reporting.

**Created by Shlok Shah**

---

## Overview

This is the client-side application for ZeroRisk Sentinel. It performs initial static analysis directly in the browser while optionally leveraging a Python backend for enhanced threat intelligence. The frontend is designed to work standalone with graceful degradation when backend services are unavailable.

---

## Frontend Structure

```
├── index.html          # Main file scanner interface
├── url.html            # URL security analysis page
├── results.html        # Detailed analysis results & reporting
├── about.html          # Documentation & methodology
├── main.js             # Core file analysis engine
├── url-analyzer.js     # URL scanning logic
└── generateReport.js   # PDF/JSON report generation
```
| 🔗 Backend Service | |
|:---|:---|
| Repository | [`zerorisk-sentinel-backend`](https://github.com/shlokkokk/zerorisk-sentinel-backend) |
| Description | Separate API layer for this frontend |

---

### Page Breakdown

| Page | Purpose |
|------|---------|
| **index.html** | File drop zone with drag-and-drop support, scan mode toggle (Live/Demo), deep scan option |
| **url.html** | URL input with demo samples, backend connectivity check, heuristic fallback |
| **results.html** | ECharts visualizations, dynamic result rendering, report export modal |
| **about.html** | Full methodology documentation, tech stack info, architecture explanation |

---

## Data Flow & API Communication

### Backend Integration

The frontend communicates with a Flask backend (configured via environment variable or constant).:

```javascript
// Backend status check on load
GET /api/status

// File scanning (non-APK files)
POST /api/scan-file
Content-Type: multipart/form-data

// APK analysis
POST /api/analyze-apk
Content-Type: multipart/form-data

// URL analysis
POST /api/analyze-url
Content-Type: application/json
{ "url": "https://example.com" }

// Hash lookup (no upload)
GET /api/scan-hash/<sha256>
```

### Graceful Degradation

When the backend is unavailable, the frontend automatically falls back to client-side analysis:

```javascript
// From url-analyzer.js
try {
  const response = await fetch(`${BACKEND_URL}/api/analyze-url`, {...});
  // Use backend results
} catch (err) {
  // Backend failed - use local heuristics
  performLocalURLAnalysis(url);
}
```

### Session Storage

Analysis results persist in `sessionStorage` for cross-page navigation:

```javascript
// Store results
sessionStorage.setItem("analysisResults", JSON.stringify(results));
sessionStorage.setItem("urlResults", JSON.stringify(urlResults));

// Retrieve on results page
const fileData = JSON.parse(sessionStorage.getItem("analysisResults") || "[]");
```

---

## UI / UX Decisions

### Visual Design

- **Cyberpunk aesthetic**: Dark theme with neon accents (cyan `#00d4ff`, green `#00ff41`)
- **Matrix background**: Canvas-based falling characters animation
- **Custom cursor**: SVG crosshair that changes color on click
- **Glassmorphism cards**: Backdrop blur with gradient borders

### Interactive Elements

| Feature | Implementation |
|---------|----------------|
| **Drag & Drop** | Native HTML5 API with visual feedback (`drag-over` class) |
| **Progress Animation** | Anime.js for smooth progress bar fills |
| **Charts** | ECharts for threat distribution (orbit visualization) and security score gauge |
| **Terminal Output** | Simulated console with color-coded log levels |
| **Page Transitions** | CSS transforms with directional exit animations |

### Scan Modes

- **Live Mode**: Real file/URL analysis with backend integration
- **Demo Mode**: Pre-configured samples for testing without uploading actual files

### Deep Scan Toggle

```javascript
// Quick Scan: Samples strategic positions (start, middle, end)
// Deep Scan: Streams entire file in 128KB chunks
const CHUNK = 128 * 1024;
while (offset < file.size) {
  const slice = file.slice(offset, offset + CHUNK);
  // Process chunk...
}
```

---

## Tech Stack

| Category | Libraries |
|----------|-----------|
| **Styling** | Tailwind CSS (CDN) |
| **Animations** | Anime.js, Typed.js |
| **Charts** | ECharts 5.4.3 |
| **PDF Generation** | jsPDF 2.5.1 |
| **Fonts** | JetBrains Mono, Inter, Orbitron (Google Fonts) |

---

## Key Features

### File Analysis (`main.js`)

- **Signature matching**: Regex-based malware pattern detection
- **File header analysis**: Magic number detection for 30+ file types
- **Extension spoofing detection**: Compares claimed extension vs actual header
- **RTL override detection**: Unicode right-to-left character detection
- **Keylogger detection**: Pattern matching for surveillance APIs
- **Spyware profile**: Surveillance, exfiltration, persistence, stealth scoring

### URL Analysis (`url-analyzer.js`)

- Backend-first with 25-second timeout
- Local fallback heuristics:
  - IP-based URL detection
  - URL shortener detection (bit.ly, tinyurl, etc.)
  - Phishing keyword matching
  - Risky TLD detection (.xyz, .tk, .ml)
  - HTTPS verification

### Report Generation (`generateReport.js`)

| Format | Features |
|--------|----------|
| **JSON** | Complete scan metadata, hashes, findings, recommendations |
| **PDF** | Professional formatted report with cover page, executive summary, threat distribution, per-file breakdown, security recommendations |

Keyboard shortcut: `Ctrl+Shift+R` opens report modal

---

## Architecture Notes

### Hybrid Analysis Flow

```
User uploads file
        │
        ▼
┌─────────────────┐
│ Client Analysis │ ← Always runs (header, extension, basic patterns)
└────────┬────────┘
         │
         ▼
┌──────────────────┐
│ Backend Available?│
└────────┬─────────┘
    Yes /│\ No
       / │ \
      ▼  │  ▼
┌───────┐│ ┌────────────────┐
│YARA   ││ │ Local Patterns │
│VT API ││ │ (fallback)     │
│Hashes ││ └────────────────┘
└───────┘│
         │
         ▼
┌─────────────────┐
│ Merge Results   │
│ Render UI       │
└─────────────────┘
```

### Security Considerations

- Files are analyzed locally first before any backend upload
- Session-only storage (cleared on tab close)
- No persistent user tracking
- Transparent processing with visible terminal output

---

## Limitations

- **Static analysis only**: No runtime execution or sandboxing
- **Browser constraints**: Cannot access system APIs or perform deep OS integration
- **File size limits**: Large files may cause performance issues in browser
- **Heuristic-based**: Results indicate risk, not definitive proof of maliciousness

---

## Future Enhancements

- WebAssembly integration for faster local analysis
- Service Worker for offline functionality
- WebSocket connection for real-time backend updates
- Additional export formats (CSV, XML)
- Dark/light theme toggle
- Multi-language support

---

**© ZeroRisk Sentinel - Shlok Shah**
