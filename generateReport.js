const REPORT_VERSION = "2.2.0";
let selectedFormat = null;

// ==================== CHART DATA CALCULATION ====================

function calculateReportChartData() {
  const fileData = JSON.parse(sessionStorage.getItem("analysisResults") || "[]");
  
  let safe = 0, warning = 0, critical = 0, totalScore = 0;
  let sandboxCount = 0;

  fileData.forEach((file) => {
    if (file.threatLevel === "safe") safe++;
    else if (file.threatLevel === "low" || file.threatLevel === "medium") warning++;
    else if (file.threatLevel === "high" || file.threatLevel === "critical") critical++;
    totalScore += file.threatScore || 0;
    if (file.deep_scan || file.sandbox_data) sandboxCount++;
  });

  const avgThreat = fileData.length ? Math.round(totalScore / fileData.length) : 0;
  return { 
    safe, 
    warning, 
    critical, 
    avgScore: Math.max(0, 100 - avgThreat),
    totalFiles: fileData.length,
    sandboxCount
  };
}

function calculateURLStats() {
  const urlData = JSON.parse(sessionStorage.getItem("urlResults") || "[]");
  
  let safe = 0, warning = 0, critical = 0;
  let backendBased = 0, localBased = 0, deepScan = 0;

  urlData.forEach((url) => {
    if (url.threatLevel === "safe" || url.threat_level === "safe") safe++;
    else if (url.threatLevel === "low" || url.threatLevel === "medium" || 
             url.threat_level === "low" || url.threat_level === "medium") warning++;
    else if (url.threatLevel === "high" || url.threatLevel === "critical" ||
             url.threat_level === "high" || url.threat_level === "critical") critical++;
    
    if (url.backend_based) backendBased++;
    else localBased++;
    
    if (url.deep_scan) deepScan++;
  });

  return {
    total: urlData.length,
    safe,
    warning,
    critical,
    backendBased,
    localBased,
    deepScan
  };
}

function openReportModal() {
  const modal = document.getElementById("reportModal");
  if (!modal) return;

  modal.style.opacity = "1";
  modal.style.visibility = "visible";
  
  const modalContent = modal.querySelector("div");
  if (modalContent) {
    modalContent.style.transform = "scale(1)";
    modalContent.style.opacity = "1";
  }

  selectedFormat = null;
  document.querySelectorAll(".format-opt").forEach((el) => {
    el.style.borderColor = "rgba(0,212,255,0.2)";
    el.style.background = "rgba(255,255,255,0.03)";
    el.style.boxShadow = "none";
    el.style.transform = "scale(1)";
  });

  const genBtn = document.getElementById("genReportBtn");
  if (genBtn) {
    genBtn.disabled = true;
    genBtn.style.opacity = "0.4";
    genBtn.style.cursor = "not-allowed";
  }
}

function closeReportModal() {
  const modal = document.getElementById("reportModal");
  if (!modal) return;

  modal.style.opacity = "0";
  modal.style.visibility = "hidden";
  
  const modalContent = modal.querySelector("div");
  if (modalContent) {
    modalContent.style.transform = "scale(0.9)";
    modalContent.style.opacity = "0";
  }
}

function selectFormat(format) {
  selectedFormat = format;

  document.querySelectorAll(".format-opt").forEach((el) => {
    el.style.borderColor = "rgba(0,212,255,0.2)";
    el.style.background = "rgba(255,255,255,0.03)";
    el.style.boxShadow = "none";
    el.style.transform = "scale(1)";
  });

  const selectedEl = document.getElementById("fmt-" + format);
  if (selectedEl) {
    selectedEl.style.borderColor = "#00d4ff";
    selectedEl.style.background = "rgba(0,212,255,0.15)";
    selectedEl.style.boxShadow = "0 0 20px rgba(0,212,255,0.3), inset 0 0 20px rgba(0,212,255,0.05)";
    selectedEl.style.transform = "scale(1.02)";
  }

  const genBtn = document.getElementById("genReportBtn");
  if (genBtn) {
    genBtn.disabled = false;
    genBtn.style.opacity = "1";
    genBtn.style.cursor = "pointer";
  }
}

// ==================== MAIN REPORT GENERATION ====================

async function generateSelectedReport() {
  if (!selectedFormat) return;

  const fileData = JSON.parse(sessionStorage.getItem("analysisResults") || "[]");
  const urlData = JSON.parse(sessionStorage.getItem("urlResults") || "[]");

  if (fileData.length === 0 && urlData.length === 0) {
    showNotification("No scan data available. Please scan files or URLs first.", "warning");
    closeReportModal();
    return;
  }

  const btn = document.getElementById("genReportBtn");
  const originalText = btn ? btn.innerHTML : "Generate Report";

  if (btn) {
    btn.innerHTML = '<span class="animate-pulse">Generating...</span>';
    btn.disabled = true;
  }

  try {
    if (selectedFormat === "json") {
      await generateJSONReport(fileData, urlData);
    } else if (selectedFormat === "pdf") {
      await generatePDFReport(fileData, urlData);
    }

    closeReportModal();
    showNotification("Report generated successfully!", "success");
  } catch (error) {
    console.error("Report generation error:", error);
    showNotification("Failed to generate report: " + error.message, "error");
  } finally {
    if (btn) {
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  }
}

// ==================== JSON REPORT ====================

async function generateJSONReport(fileData, urlData) {
  const chartData = calculateReportChartData();
  const urlStats = calculateURLStats();

  const reportData = {
    reportMetadata: {
      generatedAt: new Date().toISOString(),
      toolName: "ZeroRisk Sentinel",
      version: REPORT_VERSION,
      reportType: "Security Analysis Summary",
      reportId: generateReportId()
    },
    executiveSummary: {
      generatedAt: new Date().toLocaleString(),
      totalScans: fileData.length + urlData.length,
      filesScanned: fileData.length,
      urlsScanned: urlData.length,
      filesWithSandbox: chartData.sandboxCount,
      urlsWithDeepScan: urlStats.deepScan,
      overallSecurityScore: chartData.avgScore,
      threatBreakdown: {
        safe: chartData.safe + urlStats.safe,
        warning: chartData.warning + urlStats.warning,
        critical: chartData.critical + urlStats.critical
      },
      riskAssessment: generateRiskAssessmentText(fileData, urlData)
    },
    fileAnalysis: {
      scanned: fileData.length > 0,
      totalFiles: fileData.length,
      sandboxScans: chartData.sandboxCount,
      statistics: {
        safe: chartData.safe,
        warning: chartData.warning,
        critical: chartData.critical,
        securityScore: chartData.avgScore
      },
      files: fileData.length > 0 ? fileData.map((file) => ({
        name: file.name,
        size: file.size,
        sizeFormatted: formatBytes(file.size),
        type: file.type,
        threatLevel: file.threatLevel,
        threatScore: file.threatScore,
        hashes: file.hashes || null,
        entropy: file.entropy || null,
        fileType: file.fileType || null,
        virustotal: file.virustotal || null,
        deepScan: file.deep_scan || false,
        sandboxData: file.sandbox_data || null,
        keyloggerDetected: file.keyloggerDetected || false,
        malwareDetected: file.malwareDetected || false,
        extensionMismatch: file.extensionMismatch || false,
        riskExposure: file.riskExposure || "unknown",
        spywareProfile: file.spywareProfile || null,
        findings: file.findings || [],
        apkAnalysis: file.apkAnalysis || null,
        scanTimestamp: file.lastModified || null
      })) : []
    },
    urlAnalysis: {
      scanned: urlData.length > 0,
      totalURLs: urlData.length,
      deepScans: urlStats.deepScan,
      statistics: urlStats,
      urls: urlData.length > 0 ? urlData.map((url) => ({
        url: url.url,
        domain: url.domain,
        threatLevel: url.threat_level || url.threatLevel,
        threatScore: url.threat_score || url.threatScore,
        backendBased: url.backend_based || false,
        deepScan: url.deep_scan || false,
        services: url.services || {},
        urlscanData: url.urlscan_data || null,
        findings: url.findings || [],
        explanation: url.explanation || "",
        scanTimestamp: url.scan_time
      })) : []
    },
    recommendations: generateRecommendations(fileData, urlData)
  };

  const jsonStr = JSON.stringify(reportData, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = `zerorisk-report-${formatTimestamp()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ==================== PDF REPORT ====================

async function generatePDFReport(fileData, urlData) {
  const { jsPDF } = window.jspdf;
  if (!jsPDF) throw new Error("PDF library not loaded");

  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  let y = 20;

  const chartData = calculateReportChartData();
  const urlStats = calculateURLStats();

  // Color scheme
  const colors = {
    primary: [0, 212, 255],
    secondary: [0, 255, 65],
    warning: [255, 107, 53],
    danger: [220, 20, 60],
    dark: [10, 10, 10],
    panel: [26, 26, 26],
    gray: [128, 128, 128],
    white: [255, 255, 255],
    purple: [168, 85, 247]
  };

  // Helper functions
  const addText = (text, x, yPos, size = 11, color = colors.white, style = "normal", align = "left") => {
    doc.setFontSize(size);
    doc.setTextColor(...color);
    doc.setFont("helvetica", style);
    doc.text(text, x, yPos, { align });
    return yPos + (size * 0.4);
  };

  const drawLine = (yPos, color = colors.primary) => {
    doc.setDrawColor(...color);
    doc.setLineWidth(0.5);
    doc.line(margin, yPos, pageWidth - margin, yPos);
    return yPos + 3;
  };

  const addSectionHeader = (title, yPos) => {
    yPos = addText(title.toUpperCase(), margin, yPos, 14, colors.primary, "bold");
    yPos = drawLine(yPos);
    return yPos + 2;
  };

  const checkPageBreak = (neededSpace = 30) => {
    if (y + neededSpace > pageHeight - margin) {
      doc.addPage();
      y = 20;
      doc.setFillColor(...colors.dark);
      doc.rect(0, 0, pageWidth, 10, "F");
      addText("ZeroRisk Sentinel - Security Report", margin, 7, 8, colors.primary, "bold");
      return true;
    }
    return false;
  };

  const getThreatColor = (level) => {
    switch (level) {
      case "safe": return colors.secondary;
      case "low": return colors.primary;
      case "medium": return colors.warning;
      case "high": 
      case "critical": return colors.danger;
      default: return colors.gray;
    }
  };

  // ==================== COVER PAGE ====================
  
  doc.setFillColor(...colors.dark);
  doc.rect(0, 0, pageWidth, pageHeight, "F");

  // Gradient effect
  for (let i = 0; i < 60; i++) {
    const alpha = 0.01 + (i * 0.0008);
    doc.setFillColor(0, 212, 255);
    doc.setGState(new doc.GState({ opacity: alpha }));
    doc.rect(0, i * 5, pageWidth, 5, "F");
  }
  doc.setGState(new doc.GState({ opacity: 1 }));

  // Logo area
  y = 35;
  doc.setTextColor(...colors.primary);
  doc.setFontSize(48);
  doc.setFont("helvetica", "bold");
  doc.text("◆", pageWidth / 2, y, { align: "center" });
  y += 20;

  // Title
  y = addText("ZeroRisk Sentinel", pageWidth / 2, y, 28, colors.white, "bold", "center");
  y = addText("Security Analysis Report", pageWidth / 2, y + 5, 16, colors.primary, "normal", "center");

  y += 25;

  // Metadata box
  const metaBoxY = y;
  doc.setFillColor(...colors.panel);
  doc.setDrawColor(...colors.primary);
  doc.setLineWidth(0.3);
  doc.roundedRect(margin + 20, metaBoxY, pageWidth - (margin * 2) - 40, 50, 3, 3, "FD");

  y += 10;
  addText(`Report Generated: ${new Date().toLocaleString()}`, pageWidth / 2, y, 10, colors.gray, "normal", "center");
  y += 7;
  addText(`Version: ${REPORT_VERSION}`, pageWidth / 2, y, 10, colors.gray, "normal", "center");
  y += 7;
  addText(`Report ID: ${generateReportId()}`, pageWidth / 2, y, 10, colors.gray, "normal", "center");
  y += 7;
  
  const totalItems = fileData.length + urlData.length;
  addText(`Items Scanned: ${totalItems} (Files: ${fileData.length}, URLs: ${urlData.length})`, pageWidth / 2, y, 10, colors.white, "bold", "center");
  
  if (chartData.sandboxCount > 0 || urlStats.deepScan > 0) {
    y += 7;
    const sandboxText = [];
    if (chartData.sandboxCount > 0) sandboxText.push(`File Sandboxes: ${chartData.sandboxCount}`);
    if (urlStats.deepScan > 0) sandboxText.push(`URL Deep Scans: ${urlStats.deepScan}`);
    addText(sandboxText.join(" | "), pageWidth / 2, y, 9, colors.purple, "normal", "center");
  }

  y = metaBoxY + 60;

  // Security Score
  if (fileData.length > 0) {
    y = addText("OVERALL SECURITY SCORE", pageWidth / 2, y, 12, colors.white, "bold", "center");
    y += 10;

    const score = chartData.avgScore;
    const scoreColor = score >= 80 ? colors.secondary : score >= 60 ? colors.warning : colors.danger;

    doc.setDrawColor(...scoreColor);
    doc.setLineWidth(2);
    doc.circle(pageWidth / 2, y, 15);
    addText(`${Math.round(score)}`, pageWidth / 2, y + 5, 20, scoreColor, "bold", "center");

    y += 25;

    const statText = `Safe: ${chartData.safe}  |  Warnings: ${chartData.warning}  |  Threats: ${chartData.critical}`;
    addText(statText, pageWidth / 2, y, 11, colors.white, "normal", "center");
    y += 10;
  }

  if (fileData.length === 0 && urlData.length === 0) {
    y = addText("⚠ NO SCAN DATA AVAILABLE", pageWidth / 2, y, 14, colors.warning, "bold", "center");
    y += 8;
    addText("Scan files or URLs to generate a complete report", pageWidth / 2, y, 10, colors.gray, "normal", "center");
  }

  // Classification banner
  y = pageHeight - 35;
  doc.setFillColor(...colors.primary);
  doc.rect(0, y, pageWidth, 12, "F");
  addText("CONFIDENTIAL SECURITY REPORT", pageWidth / 2, y + 4, 10, colors.dark, "bold", "center");

  y += 18;
  addText("Generated by ZeroRisk Sentinel Advanced Security Scanner", pageWidth / 2, y, 8, colors.gray, "normal", "center");

  // ==================== EXECUTIVE SUMMARY ====================
  
  doc.addPage();
  y = 20;

  y = addSectionHeader("Executive Summary", y);

  // Summary box
  doc.setFillColor(...colors.panel);
  doc.roundedRect(margin, y, pageWidth - (margin * 2), 65, 2, 2, "F");

  let boxY = y + 8;
  addText(`Total Items Analyzed: ${fileData.length + urlData.length}`, margin + 5, boxY, 11, colors.white);
  boxY += 8;
  addText(`Files Scanned: ${fileData.length}`, margin + 5, boxY, 11, colors.white);
  boxY += 8;
  addText(`URLs Scanned: ${urlData.length}`, margin + 5, boxY, 11, colors.white);
  
  if (chartData.sandboxCount > 0) {
    boxY += 8;
    addText(`Files with Sandbox: ${chartData.sandboxCount}`, margin + 5, boxY, 11, colors.purple, "bold");
  }
  
  if (urlStats.deepScan > 0) {
    boxY += 8;
    addText(`URLs with Deep Scan: ${urlStats.deepScan}`, margin + 5, boxY, 11, colors.purple, "bold");
  }
  
  boxY += 8;

  if (fileData.length > 0) {
    addText(`Overall Security Score: ${chartData.avgScore}/100`, margin + 5, boxY, 11, colors.white, "bold");
    boxY += 8;

    const riskText = chartData.avgScore >= 80 ? "LOW RISK" : chartData.avgScore >= 60 ? "MODERATE RISK" : "HIGH RISK";
    const riskColor = chartData.avgScore >= 80 ? colors.secondary : chartData.avgScore >= 60 ? colors.warning : colors.danger;
    addText(`Risk Assessment: ${riskText}`, margin + 5, boxY, 11, riskColor, "bold");
  }

  y += 75;

  // Threat Distribution
  if (fileData.length > 0 || urlData.length > 0) {
    checkPageBreak(40);
    y = addSectionHeader("Threat Distribution", y);

    doc.setFillColor(...colors.panel);
    doc.roundedRect(margin, y, pageWidth - (margin * 2), 35, 2, 2, "F");

    const totalSafe = chartData.safe + urlStats.safe;
    const totalWarning = chartData.warning + urlStats.warning;
    const totalCritical = chartData.critical + urlStats.critical;

    addText(`● Safe: ${totalSafe}`, margin + 10, y + 10, 11, colors.secondary);
    addText(`● Warnings: ${totalWarning}`, margin + 70, y + 10, 11, colors.warning);
    addText(`● Critical: ${totalCritical}`, margin + 130, y + 10, 11, colors.danger);
    
    let scanY = y + 22;
    if (chartData.sandboxCount > 0) {
      addText(`● File Sandboxes: ${chartData.sandboxCount}`, margin + 10, scanY, 10, colors.purple);
      scanY += 6;
    }
    if (urlStats.deepScan > 0) {
      addText(`● URL Deep Scans: ${urlStats.deepScan}`, margin + 10, scanY, 10, colors.purple);
    }

    y += 45;
  }

  // Risk Assessment Text
  checkPageBreak(40);
  y = addSectionHeader("Assessment Details", y);

  const assessment = generateRiskAssessmentText(fileData, urlData);
  const lines = doc.splitTextToSize(assessment, pageWidth - (margin * 2) - 10);

  doc.setFillColor(...colors.panel);
  doc.roundedRect(margin, y, pageWidth - (margin * 2), lines.length * 5 + 10, 2, 2, "F");

  doc.setTextColor(200, 200, 200);
  doc.setFontSize(10);
  doc.text(lines, margin + 5, y + 8);

  y += lines.length * 5 + 20;

  // ==================== FILE ANALYSIS SECTION ====================

  if (fileData.length > 0) {
    doc.addPage();
    y = 20;
    y = addSectionHeader("File Security Analysis", y);

    fileData.forEach((file, index) => {
      const boxHeight = calculateFileBoxHeight(file);
      checkPageBreak(boxHeight + 10);

      const threatColor = getThreatColor(file.threatLevel);
      const hasSandbox = file.deep_scan || file.sandbox_data;

      // File header box
      doc.setFillColor(...colors.panel);
      doc.setDrawColor(...threatColor);
      doc.setLineWidth(0.5);
      doc.roundedRect(margin, y, pageWidth - (margin * 2), hasSandbox ? 16 : 12, 2, 2, "FD");

      // File name and threat level
      const displayName = (file.name || "Unknown").length > 45 
        ? (file.name || "Unknown").substring(0, 42) + "..." 
        : (file.name || "Unknown");
      
      addText(`${index + 1}. ${displayName}`, margin + 3, y + 4, 10, colors.white, "bold");
      
      if (hasSandbox) {
        addText((file.threatLevel || "unknown").toUpperCase(), pageWidth - margin - 50, y + 4, 9, threatColor, "bold", "right");
        addText("[SANDBOX]", pageWidth - margin - 3, y + 4, 8, colors.purple, "bold", "right");
      } else {
        addText((file.threatLevel || "unknown").toUpperCase(), pageWidth - margin - 3, y + 4, 9, threatColor, "bold", "right");
      }

      y += hasSandbox ? 19 : 15;

      // File details
      doc.setFillColor(...colors.panel);
      doc.roundedRect(margin, y - 3, pageWidth - (margin * 2), boxHeight - 15, 2, 2, "F");

      let detailY = y + 5;
      addText(`Threat Score: ${file.threatScore || 0}/100`, margin + 5, detailY, 9, colors.white);
      detailY += 6;
      addText(`Size: ${formatBytes(file.size)}`, margin + 5, detailY, 9, colors.gray);
      detailY += 6;
      addText(`Keylogger: ${file.keyloggerDetected ? "⚠ DETECTED" : "Not detected"}`, margin + 5, detailY, 9, file.keyloggerDetected ? colors.danger : colors.gray);
      detailY += 6;
      addText(`Extension Spoofing: ${file.extensionMismatch ? "⚠ YES" : "No"}`, margin + 5, detailY, 9, file.extensionMismatch ? colors.danger : colors.gray);

      // Sandbox info
      if (file.sandbox_data) {
        detailY += 6;
        const sd = file.sandbox_data;
        addText(`Sandbox: ${sd.verdict || "N/A"} | Processes: ${sd.processes_spawned || 0} | Network: ${sd.network_connections || 0}`, margin + 5, detailY, 8, colors.purple);
      }

      // Hashes
      if (file.hashes && file.hashes.sha256) {
        detailY += 6;
        doc.setTextColor(100, 100, 100);
        doc.setFontSize(7);
        doc.text(`SHA256: ${file.hashes.sha256.substring(0, 40)}...`, margin + 5, detailY);
      }

      detailY += 8;

      // Spyware Profile
      if (file.spywareProfile) {
        addText("Behavior Profile:", margin + 5, detailY, 9, colors.white, "bold");
        detailY += 5;

        const profile = file.spywareProfile;
        const behaviors = [
          `Surveillance: ${profile.surveillance ? "✓" : "✗"}`,
          `Data Exfiltration: ${profile.dataExfiltration ? "✓" : "✗"}`,
          `Persistence: ${profile.persistence ? "✓" : "✗"}`,
          `Stealth: ${profile.stealth ? "✓" : "✗"}`
        ];

        behaviors.forEach((b) => {
          addText(`  ${b}`, margin + 8, detailY, 8, colors.gray);
          detailY += 4;
        });
      }

      // Findings
      if (file.findings && file.findings.length > 0) {
        detailY += 3;
        addText("Findings:", margin + 5, detailY, 9, colors.white, "bold");
        detailY += 5;

        file.findings.slice(0, 3).forEach((finding) => {
          const sevColor = finding.severity === "critical" || finding.severity === "high" ? colors.danger : 
                          finding.severity === "medium" ? colors.warning : colors.secondary;
          
          const shortDesc = (finding.description || finding).length > 55 
            ? (finding.description || finding).substring(0, 52) + "..." 
            : (finding.description || finding);

          addText(`[${(finding.severity || "info").toUpperCase()}]`, margin + 8, detailY, 8, sevColor, "bold");
          addText(shortDesc, margin + 30, detailY, 8, colors.gray);
          detailY += 4;
        });
      }

      // Risk Explanation
      if (file.riskExposure && file.riskExposure !== "unknown") {
        detailY += 3;
        const shortExp = file.riskExposure.length > 90 
          ? file.riskExposure.substring(0, 87) + "..." 
          : file.riskExposure;
        addText(`Assessment: ${shortExp}`, margin + 5, detailY, 8, colors.gray);
      }

      y += boxHeight;
      y = drawLine(y, colors.gray);
      y += 3;
    });
  } else {
    doc.addPage();
    y = 20;
    y = addSectionHeader("File Security Analysis", y);
    
    doc.setFillColor(...colors.panel);
    doc.roundedRect(margin, y, pageWidth - (margin * 2), 30, 2, 2, "F");
    
    addText("No files were scanned during this session.", margin + 10, y + 12, 12, colors.gray, "bold");
    addText("Use the File Scanner to analyze files for malware, spyware, and other threats.", margin + 10, y + 22, 10, colors.gray);
  }

  // ==================== URL ANALYSIS SECTION ====================

  if (urlData.length > 0) {
    doc.addPage();
    y = 20;
    y = addSectionHeader("URL Security Analysis", y);

    urlData.forEach((url, index) => {
      checkPageBreak(50);

      const threatLevel = url.threat_level || url.threatLevel || "unknown";
      const threatColor = getThreatColor(threatLevel);
      const isDeepScan = url.deep_scan || url.deepScan;

      // URL header box
      doc.setFillColor(...colors.panel);
      doc.setDrawColor(...threatColor);
      doc.roundedRect(margin, y, pageWidth - (margin * 2), isDeepScan ? 16 : 12, 2, 2, "FD");

      const displayUrl = (url.url || "").length > 50 
        ? (url.url || "").substring(0, 47) + "..." 
        : (url.url || "");
      
      addText(`${index + 1}. ${displayUrl}`, margin + 3, y + 4, 9, colors.white, "bold");
      addText(threatLevel.toUpperCase(), pageWidth - margin - 3, y + 4, 9, threatColor, "bold", "right");
      
      if (isDeepScan) {
        addText("[DEEP SCAN]", pageWidth - margin - 45, y + 4, 8, colors.purple, "bold", "right");
      }

      y += isDeepScan ? 19 : 15;

      // URL details
      const detailsHeight = isDeepScan ? 40 : 22;
      doc.setFillColor(...colors.panel);
      doc.roundedRect(margin, y - 3, pageWidth - (margin * 2), detailsHeight, 2, 2, "F");

      addText(`Domain: ${url.domain || "N/A"}`, margin + 5, y + 5, 9, colors.gray);
      addText(`Score: ${url.threat_score || url.threatScore || 0}/100`, margin + 80, y + 5, 9, colors.white);
      
      const scanType = url.backend_based ? "Backend Intelligence" : "Local Heuristic";
      addText(`Type: ${scanType}`, margin + 130, y + 5, 8, colors.gray);

      // Deep Scan info
      if (isDeepScan && url.urlscan_data) {
        const us = url.urlscan_data;
        const ns = us.network_stats || {};
        addText(`Network Requests: ${ns.total_requests || 0}`, margin + 5, y + 14, 8, colors.gray);
        addText(`Suspicious Domains: ${ns.suspicious_domains || 0}`, margin + 80, y + 14, 8, ns.suspicious_domains > 0 ? colors.danger : colors.gray);
        addText(`Server: ${us.server || "N/A"}`, margin + 130, y + 14, 8, colors.gray);
        
        if (us.ip) {
          addText(`IP: ${us.ip}`, margin + 5, y + 23, 8, colors.gray);
        }
        if (us.country) {
          addText(`Country: ${us.country}`, margin + 80, y + 23, 8, colors.gray);
        }
        if (us.brands_detected && us.brands_detected.length > 0) {
          addText(`Brands: ${us.brands_detected.slice(0, 2).join(", ")}`, margin + 5, y + 32, 8, colors.warning);
        }
      }

      // External services
      let serviceY = y + (isDeepScan ? 36 : 12);
      if (url.services) {
        const gsb = url.services.google_safe_browsing;
        if (gsb && gsb.available) {
          const status = gsb.threat_found ? `THREAT: ${gsb.threat_type}` : "Safe";
          const statusColor = gsb.threat_found ? colors.danger : colors.secondary;
          addText(`Google Safe Browsing:`, margin + 5, serviceY, 8, colors.gray);
          addText(status, margin + 55, serviceY, 8, statusColor, "bold");
        }

        const uh = url.services.urlhaus;
        if (uh && uh.available) {
          serviceY += 5;
          const status = uh.listed ? "LISTED" : "Not Listed";
          const statusColor = uh.listed ? colors.danger : colors.secondary;
          addText(`URLHaus:`, margin + 5, serviceY, 8, colors.gray);
          addText(status, margin + 55, serviceY, 8, statusColor, "bold");
        }
        
        const vt = url.services.virustotal_url;
        if (vt && vt.available) {
          serviceY += 5;
          const status = `${vt.malicious || 0}/${vt.total || 70} flagged`;
          const statusColor = (vt.malicious || 0) > 0 ? colors.danger : colors.secondary;
          addText(`VirusTotal:`, margin + 5, serviceY, 8, colors.gray);
          addText(status, margin + 55, serviceY, 8, statusColor, "bold");
        }
      }

      y += detailsHeight + 10;

      // Findings
      if (url.findings && url.findings.length > 0) {
        checkPageBreak(20);
        addText("Indicators:", margin + 5, y, 9, colors.white, "bold");
        y += 5;

        url.findings.slice(0, 2).forEach((f) => {
          const shortDesc = (f.description || "").length > 55 
            ? (f.description || "").substring(0, 52) + "..." 
            : (f.description || "");
          addText(`• ${shortDesc}`, margin + 8, y, 8, colors.gray);
          y += 4;
        });
      }

      y += 5;
      y = drawLine(y, colors.gray);
      y += 3;
    });
  } else {
    doc.addPage();
    y = 20;
    y = addSectionHeader("URL Security Analysis", y);
    
    doc.setFillColor(...colors.panel);
    doc.roundedRect(margin, y, pageWidth - (margin * 2), 30, 2, 2, "F");
    
    addText("No URLs were scanned during this session.", margin + 10, y + 12, 12, colors.gray, "bold");
    addText("Use the URL Scanner to analyze web addresses for phishing and malware.", margin + 10, y + 22, 10, colors.gray);
  }

  // ==================== RECOMMENDATIONS ====================

  doc.addPage();
  y = 20;
  y = addSectionHeader("Recommendations", y);

  const recommendations = generateRecommendations(fileData, urlData);
  
  recommendations.forEach((rec, i) => {
    checkPageBreak(25);
    
    doc.setFillColor(...colors.panel);
    doc.roundedRect(margin, y, pageWidth - (margin * 2), 20, 2, 2, "F");
    
    addText(`${i + 1}. ${rec.title}`, margin + 5, y + 6, 10, colors.primary, "bold");
    
    const descLines = doc.splitTextToSize(rec.description, pageWidth - (margin * 2) - 15);
    doc.setTextColor(200, 200, 200);
    doc.setFontSize(9);
    doc.text(descLines, margin + 5, y + 12);
    
    y += 25;
  });

  // ==================== FOOTER ====================

  const totalPages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    
    doc.setFillColor(26, 26, 26);
    doc.rect(0, pageHeight - 12, pageWidth, 12, "F");
    
    doc.setDrawColor(...colors.primary);
    doc.setLineWidth(0.3);
    doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);
    
    addText(`ZeroRisk Sentinel v${REPORT_VERSION} | Page ${i} of ${totalPages}`, pageWidth / 2, pageHeight - 6, 8, colors.gray, "normal", "center");
  }

  doc.save(`zerorisk-report-${formatTimestamp()}.pdf`);
}

// ==================== HELPER FUNCTIONS ====================

function calculateFileBoxHeight(file) {
  let height = 35;
  
  if (file.hashes && file.hashes.sha256) height += 6;
  if (file.sandbox_data) height += 6;
  if (file.spywareProfile) height += 25;
  if (file.findings && file.findings.length > 0) height += 20;
  if (file.riskExposure && file.riskExposure !== "unknown") height += 10;
  
  return Math.min(height, 110);
}

function generateRiskAssessmentText(fileData, urlData) {
  const chartData = calculateReportChartData();
  const urlStats = calculateURLStats();
  
  let text = "";
  
  if (fileData.length === 0 && urlData.length === 0) {
    return "No scan data available. Please perform file or URL scans to generate a security assessment.";
  }
  
  if (fileData.length > 0) {
    text += `File Analysis: ${fileData.length} file(s) scanned. `;
    text += `Security Score: ${chartData.avgScore}/100. `;
    
    if (chartData.sandboxCount > 0) {
      text += `${chartData.sandboxCount} file(s) analyzed with sandbox execution. `;
    }
    
    if (chartData.critical > 0) {
      text += `CRITICAL: ${chartData.critical} file(s) require immediate attention. `;
    } else if (chartData.warning > 0) {
      text += `${chartData.warning} file(s) show suspicious patterns. `;
    } else {
      text += "All files appear safe. ";
    }
  }
  
  if (urlData.length > 0) {
    if (text) text += "\n\n";
    text += `URL Analysis: ${urlData.length} URL(s) scanned. `;
    
    if (urlStats.deepScan > 0) {
      text += `${urlStats.deepScan} URL(s) analyzed with Deep Scan sandboxing. `;
    }
    
    if (urlStats.critical > 0) {
      text += `WARNING: ${urlStats.critical} malicious URL(s) detected. Avoid these sites. `;
    } else if (urlStats.warning > 0) {
      text += `${urlStats.warning} URL(s) show suspicious indicators. `;
    } else {
      text += "All URLs appear safe. ";
    }
  }
  
  return text;
}

function generateRecommendations(fileData, urlData) {
  const recs = [];
  const chartData = calculateReportChartData();
  const urlStats = calculateURLStats();
  
  const hasCriticalFiles = chartData.critical > 0;
  const hasCriticalURLs = urlStats.critical > 0;
  
  if (hasCriticalFiles || hasCriticalURLs) {
    recs.push({
      title: "Immediate Action Required",
      description: `Critical threats detected (${chartData.critical} files, ${urlStats.critical} URLs). Quarantine affected files immediately and avoid flagged URLs. Perform full system scan.`
    });
  }
  
  if (fileData.length > 0) {
    const hasKeyloggers = fileData.some(f => f.keyloggerDetected);
    const hasSpoofing = fileData.some(f => f.extensionMismatch);
    const hasSandbox = chartData.sandboxCount > 0;
    
    if (hasKeyloggers) {
      recs.push({
        title: "Credential Security Alert",
        description: "Keylogger signatures detected. Change all passwords from a clean device, enable 2FA, and check for unauthorized account access."
      });
    }
    
    if (hasSpoofing) {
      recs.push({
        title: "Extension Spoofing Detected",
        description: "Files with misleading extensions found. Always verify actual file types before opening. Enable 'Show file extensions' in your OS settings."
      });
    }
    
    if (hasSandbox) {
      recs.push({
        title: "Sandbox Analysis Complete",
        description: `${chartData.sandboxCount} file(s) were analyzed using real-time sandbox execution. Review process activity and network connections for additional context.`
      });
    }
    
    if (chartData.warning > 0 && !hasCriticalFiles) {
      recs.push({
        title: "Review Warning Files",
        description: `${chartData.warning} file(s) show suspicious patterns. Review individually and consider sandbox analysis before use.`
      });
    }
    
    recs.push({
      title: "Enable Real-time Protection",
      description: "Use antivirus with real-time scanning and behavioral analysis to catch threats before execution."
    });
  }
  
  if (urlData.length > 0) {
    if (urlStats.critical > 0 || urlStats.high > 0) {
      recs.push({
        title: "Avoid Malicious Websites",
        description: "Multiple dangerous URLs detected. Do not visit these sites. Clear browser cache and check for unauthorized redirects."
      });
    }
    
    if (urlStats.deepScan > 0) {
      recs.push({
        title: "Deep Scan Analysis Complete",
        description: `${urlStats.deepScan} URL(s) were analyzed using live browser sandboxing. Review screenshots and network activity for additional context.`
      });
    }
    
    const hasLocalOnly = urlStats.localBased > 0;
    if (hasLocalOnly) {
      recs.push({
        title: "Backend Analysis Unavailable",
        description: "Some URLs used local heuristic analysis only. Re-scan when backend is online for complete threat intelligence."
      });
    }
    
    recs.push({
      title: "Browser Security",
      description: "Keep browsers updated, use HTTPS-Everywhere, and install security extensions to block phishing and malware sites."
    });
  }
  
  recs.push({
    title: "Regular Security Scanning",
    description: "Schedule weekly scans of downloads and system directories. Maintain updated threat signatures."
  });
  
  recs.push({
    title: "Backup Strategy",
    description: "Maintain offline backups of critical data. Use 3-2-1 rule: 3 copies, 2 different media, 1 offsite."
  });
  
  return recs;
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function formatTimestamp() {
  const now = new Date();
  return now.getFullYear() + 
         String(now.getMonth() + 1).padStart(2, "0") + 
         String(now.getDate()).padStart(2, "0") + "_" +
         String(now.getHours()).padStart(2, "0") +
         String(now.getMinutes()).padStart(2, "0");
}

function generateReportId() {
  return "ZRS-" + Math.random().toString(36).substring(2, 10).toUpperCase();
}

// ==================== NOTIFICATION ====================

function showNotification(message, type = "info") {
  const existing = document.querySelectorAll(".zerorisk-notification");
  existing.forEach(n => n.remove());

  const notification = document.createElement("div");
  notification.className = `zerorisk-notification fixed top-20 right-4 z-50 p-4 rounded-lg shadow-lg max-w-sm transform transition-all duration-300 translate-x-full ${
    type === "success" ? "bg-green-600" :
    type === "warning" ? "bg-yellow-600" :
    type === "error" ? "bg-red-600" : "bg-blue-600"
  } text-white`;

  notification.innerHTML = `
    <div class="flex items-center space-x-3">
      <div class="flex-shrink-0">
        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
        </svg>
      </div>
      <div class="flex-1">
        <p class="text-sm font-medium">${message}</p>
      </div>
      <div class="flex-shrink-0">
        <button onclick="this.parentElement.parentElement.parentElement.remove()" class="text-white hover:text-gray-200">
          <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
          </svg>
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(notification);

  setTimeout(() => {
    notification.classList.remove("translate-x-full");
  }, 100);

  setTimeout(() => {
    notification.classList.add("translate-x-full");
    setTimeout(() => notification.remove(), 300);
  }, 5000);
}