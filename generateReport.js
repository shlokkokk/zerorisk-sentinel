function calculateReportChartData() {
  const storedResults = sessionStorage.getItem("analysisResults");
  if (!storedResults) return { safe: 0, warning: 0, critical: 0, avgScore: 0 };

  const results = JSON.parse(storedResults);
  let safe = 0, warning = 0, critical = 0, totalScore = 0;

  results.forEach((file) => {
    if (file.threatLevel === "safe") safe++;
    else if (file.threatLevel === "low" || file.threatLevel === "medium") warning++;
    else if (file.threatLevel === "high" || file.threatLevel === "critical") critical++;
    totalScore += file.threatScore || 0;
  });

  const avgThreat = results.length ? Math.round(totalScore / results.length) : 0;
  return { safe, warning, critical, avgScore: Math.max(0, 100 - avgThreat) };
}

function openReportModal() {
  const modal = document.getElementById('reportModal');
  if (!modal) return;
  
  modal.style.opacity = '1';
  modal.style.visibility = 'visible';
  modal.querySelector('div').style.transform = 'scale(1)';
  modal.querySelector('div').style.opacity = '1';

  selectedFormat = null;
  document.querySelectorAll('.format-opt').forEach(el => {
    el.style.borderColor = 'rgba(0,212,255,0.2)';
    el.style.background = 'rgba(255,255,255,0.03)';
    el.style.boxShadow = 'none';
  });
  
  const genBtn = document.getElementById('genReportBtn');
  if (genBtn) {
    genBtn.disabled = true;
    genBtn.style.opacity = '0.4';
    genBtn.style.cursor = 'not-allowed';
  }
}

function closeReportModal() {
  const modal = document.getElementById('reportModal');
  if (!modal) return;
  
  modal.style.opacity = '0';
  modal.style.visibility = 'hidden';
  modal.querySelector('div').style.transform = 'scale(0.9)';
  modal.querySelector('div').style.opacity = '0';
}

function selectFormat(format) {
  selectedFormat = format;

  document.querySelectorAll('.format-opt').forEach(el => {
    el.style.borderColor = 'rgba(0,212,255,0.2)';
    el.style.background = 'rgba(255,255,255,0.03)';
    el.style.boxShadow = 'none';
    el.style.transform = 'scale(1)';
  });

  const selectedEl = document.getElementById('fmt-' + format);
  if (selectedEl) {
    selectedEl.style.borderColor = '#00d4ff';
    selectedEl.style.background = 'rgba(0,212,255,0.15)';
    selectedEl.style.boxShadow = '0 0 20px rgba(0,212,255,0.3), inset 0 0 20px rgba(0,212,255,0.05)';
    selectedEl.style.transform = 'scale(1.02)';
  }

  const genBtn = document.getElementById('genReportBtn');
  if (genBtn) {
    genBtn.disabled = false;
    genBtn.style.opacity = '1';
    genBtn.style.cursor = 'pointer';
  }
}

async function generateSelectedReport() {
  if (!selectedFormat) return;

  const btn = document.getElementById('genReportBtn');
  const originalText = btn ? btn.textContent : 'Generate Report';
  
  if (btn) {
    btn.innerHTML = '<span class="animate-pulse">Generating...</span>';
    btn.disabled = true;
  }

  try {
    if (selectedFormat === 'json') await generateJSONReport();
    else if (selectedFormat === 'pdf') await generatePDFReport();
    
    closeReportModal();
    showNotification('Report generated successfully!', 'success');
  } catch (error) {
    showNotification('Failed to generate report: ' + error.message, 'error');
  } finally {
    if (btn) {
      btn.textContent = originalText;
      btn.disabled = false;
    }
  }
}

async function generateJSONReport() {
  const fileData = JSON.parse(sessionStorage.getItem('analysisResults') || '[]');
  const urlData = JSON.parse(sessionStorage.getItem('urlResults') || '[]');
  const chartData = calculateReportChartData();

  const reportData = {
    reportMetadata: {
      generatedAt: new Date().toISOString(),
      toolName: 'ZeroRisk Sentinel',
      version: '2.1',
      reportType: 'Security Analysis Summary'
    },
    summary: {
      totalFilesAnalyzed: fileData.length,
      totalURLsAnalyzed: urlData.length,
      overallSecurityScore: chartData.avgScore,
      threatDistribution: chartData
    },
    fileAnalysis: fileData.map(file => ({
      name: file.name,
      size: file.size,
      type: file.type,
      threatLevel: file.threatLevel,
      threatScore: file.threatScore,
      hashes: file.hashes || {},
      entropy: file.entropy,
      fileType: file.fileType,
      virustotal: file.virustotal,
      keyloggerDetected: file.keyloggerDetected,
      malwareDetected: file.malwareDetected,
      extensionMismatch: file.extensionMismatch,
      riskExposure: file.riskExposure,
      spywareProfile: file.spywareProfile,
      findings: file.findings,
      aiExplanation: file._aiExplanation || null
    })),
    urlAnalysis: urlData
  };

  const jsonStr = JSON.stringify(reportData, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `zerorisk-report-${new Date().toISOString().split('T')[0]}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function generatePDFReport() {
  const { jsPDF } = window.jspdf;
  if (!jsPDF) throw new Error('PDF library not loaded');
  
  const doc = new jsPDF();
  const fileData = JSON.parse(sessionStorage.getItem('analysisResults') || '[]');
  const urlData = JSON.parse(sessionStorage.getItem('urlResults') || '[]');
  const chartData = calculateReportChartData();

  const primaryColor = [0, 212, 255];
  const greenColor = [0, 255, 65];
  const redColor = [220, 20, 60];
  const yellowColor = [255, 107, 53];
  const darkBg = [10, 10, 10];
  const panelBg = [26, 26, 26];

  doc.setFillColor(...darkBg);
  doc.rect(0, 0, 210, 297, 'F');

  doc.setFillColor(...panelBg);
  doc.roundedRect(10, 10, 190, 35, 3, 3, 'F');

  doc.setTextColor(...primaryColor);
  doc.setFontSize(28);
  doc.setFont('helvetica', 'bold');
  doc.text('ZeroRisk Sentinel', 20, 30);

  doc.setTextColor(200, 200, 200);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 40);
  doc.text(`ID: ZRS-${Date.now().toString(36).toUpperCase().slice(-8)}`, 140, 40);

  doc.setDrawColor(...primaryColor);
  doc.setLineWidth(0.5);
  doc.line(20, 55, 190, 55);

  doc.setTextColor(...primaryColor);
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  doc.text('Executive Summary', 20, 70);

  doc.setFillColor(...panelBg);
  doc.roundedRect(20, 78, 170, 45, 2, 2, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  
  let y = 88;
  doc.text(`Files Analyzed: ${fileData.length}`, 30, y);
  y += 8;
  doc.text(`URLs Analyzed: ${urlData.length}`, 30, y);
  y += 8;
  doc.text(`Security Score: ${chartData.avgScore}/100`, 30, y);
  y += 8;

  let threatColor = greenColor;
  let threatText = 'LOW RISK';
  if (chartData.avgScore < 40) { threatColor = redColor; threatText = 'CRITICAL RISK'; }
  else if (chartData.avgScore < 70) { threatColor = yellowColor; threatText = 'MODERATE RISK'; }

  doc.setTextColor(...threatColor);
  doc.setFont('helvetica', 'bold');
  doc.text(`Status: ${threatText}`, 30, y);

  doc.setTextColor(...primaryColor);
  doc.setFontSize(18);
  doc.text('Threat Distribution', 20, 135);

  doc.setFillColor(...panelBg);
  doc.roundedRect(20, 142, 170, 30, 2, 2, 'F');

  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');

  doc.setTextColor(...greenColor);
  doc.text(`● Safe: ${chartData.safe}`, 35, 155);
  doc.setTextColor(...yellowColor);
  doc.text(`● Warnings: ${chartData.warning}`, 85, 155);
  doc.setTextColor(...redColor);
  doc.text(`● Critical: ${chartData.critical}`, 135, 155);

  let yPos = 185;

  if (fileData.length > 0) {
    doc.setTextColor(...primaryColor);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('Detailed File Analysis', 20, yPos);
    yPos += 12;

    fileData.forEach((file, index) => {
      const needsNewPage = yPos > 240;
      if (needsNewPage) { 
        doc.addPage(); 
        doc.setFillColor(...darkBg); 
        doc.rect(0, 0, 210, 297, 'F'); 
        yPos = 20; 
      }

      const boxHeight = file.findings?.length > 2 ? 50 : 35;
      
      doc.setFillColor(...panelBg);
      doc.roundedRect(20, yPos - 8, 170, boxHeight, 2, 2, 'F');

      doc.setTextColor(255, 255, 255);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text(`${index + 1}. ${(file.name || 'Unknown').substring(0, 40)}`, 30, yPos);

      let fileColor = greenColor;
      if (file.threatLevel === 'critical' || file.threatLevel === 'high') fileColor = redColor;
      else if (file.threatLevel === 'medium') fileColor = yellowColor;

      doc.setTextColor(...fileColor);
      doc.setFontSize(9);
      doc.text(`${(file.threatLevel || 'unknown').toUpperCase()} | Score: ${file.threatScore || 0}/100`, 30, yPos + 6);

      doc.setTextColor(150, 150, 150);
      doc.text(`${((file.size || 0) / 1024).toFixed(1)} KB`, 140, yPos + 6);

      if (file.hashes?.sha256) {
        doc.setTextColor(100, 100, 100);
        doc.setFontSize(7);
        doc.text(`SHA256: ${file.hashes.sha256.substring(0, 32)}...`, 30, yPos + 12);
      }

      if (file.findings && file.findings.length > 0) {
        doc.setTextColor(...yellowColor);
        doc.setFontSize(8);
        doc.text('Detections:', 30, yPos + 18);
        
        doc.setTextColor(200, 200, 200);
        file.findings.slice(0, 2).forEach((finding, i) => {
          const text = `- ${finding.description || finding}`.substring(0, 55);
          doc.text(text, 35, yPos + 23 + (i * 4));
        });
      }

      yPos += boxHeight + 5;
    });
  }

  if (urlData.length > 0) {
    if (yPos > 240) { 
      doc.addPage(); 
      doc.setFillColor(...darkBg); 
      doc.rect(0, 0, 210, 297, 'F'); 
      yPos = 20; 
    }

    doc.setTextColor(...primaryColor);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('URL Analysis', 20, yPos);
    yPos += 12;

    urlData.forEach((url, index) => {
      if (yPos > 270) { 
        doc.addPage(); 
        doc.setFillColor(...darkBg); 
        doc.rect(0, 0, 210, 297, 'F'); 
        yPos = 20; 
      }

      doc.setFillColor(...panelBg);
      doc.roundedRect(20, yPos - 8, 170, 20, 2, 2, 'F');

      doc.setTextColor(255, 255, 255);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text(`${index + 1}. ${(url.url || '').substring(0, 50)}`, 30, yPos);

      let urlColor = greenColor;
      if (url.threatLevel === 'critical' || url.threatLevel === 'high') urlColor = redColor;
      else if (url.threatLevel === 'medium') urlColor = yellowColor;

      doc.setTextColor(...urlColor);
      doc.setFontSize(8);
      doc.text(`${(url.threatLevel || 'unknown').toUpperCase()} | ${url.threatScore || 0}/100`, 30, yPos + 5);

      yPos += 22;
    });
  }

  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFillColor(26, 26, 26);
    doc.rect(0, 287, 210, 10, 'F');
    doc.setTextColor(100, 100, 100);
    doc.setFontSize(8);
    doc.text(`ZeroRisk Sentinel v2.1 | ${i}/${pageCount}`, 105, 293, { align: 'center' });
  }

  doc.save(`zerorisk-report-${new Date().toISOString().split('T')[0]}.pdf`);
}