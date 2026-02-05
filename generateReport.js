//  REPORT GENERATION SYSTEM 
// ZeroRisk Sentinel - Report Generator
// This file handles JSON and PDF report generation

let selectedFormat = null;

// Helper function to calculate chart data for reports
function calculateReportChartData() {
  const storedResults = sessionStorage.getItem("analysisResults");
  if (!storedResults) {
    return { safe: 0, warning: 0, critical: 0, avgScore: 0 };
  }

  const results = JSON.parse(storedResults);

  let safe = 0, warning = 0, critical = 0;
  let totalScore = 0;

  results.forEach((file) => {
    if (file.threatLevel === "safe") safe++;
    else if (file.threatLevel === "low" || file.threatLevel === "medium") warning++;
    else if (file.threatLevel === "high" || file.threatLevel === "critical") critical++;
    totalScore += file.threatScore || 0;
  });

  const avgThreat = results.length ? Math.round(totalScore / results.length) : 0;
  const avgScore = Math.max(0, 100 - avgThreat);

  return { safe, warning, critical, avgScore };
}

// Open the report format modal
function openReportModal() {
  const modal = document.getElementById('reportModal');
  if (!modal) return;
  
  modal.style.opacity = '1';
  modal.style.visibility = 'visible';
  modal.querySelector('div').style.transform = 'scale(1)';
  modal.querySelector('div').style.opacity = '1';

  // Reset selection
  selectedFormat = null;
  document.querySelectorAll('.format-opt').forEach(el => {
    el.style.borderColor = 'rgba(0,212,255,0.2)';
    el.style.background = 'rgba(255,255,255,0.03)';
  });
  const genBtn = document.getElementById('genReportBtn');
  if (genBtn) {
    genBtn.disabled = true;
    genBtn.style.opacity = '0.5';
  }
}

// Close the report format modal
function closeReportModal() {
  const modal = document.getElementById('reportModal');
  if (!modal) return;
  
  modal.style.opacity = '0';
  modal.style.visibility = 'hidden';
  modal.querySelector('div').style.transform = 'scale(0.9)';
  modal.querySelector('div').style.opacity = '0';
}

// Select report format (JSON or PDF)
function selectFormat(format) {
  selectedFormat = format;

  // Visual selection
  document.querySelectorAll('.format-opt').forEach(el => {
    el.style.borderColor = 'rgba(0,212,255,0.2)';
    el.style.background = 'rgba(255,255,255,0.03)';
  });

  const selectedEl = document.getElementById('fmt-' + format);
  if (selectedEl) {
    selectedEl.style.borderColor = '#00d4ff';
    selectedEl.style.background = 'rgba(0,212,255,0.1)';
  }

  // Enable generate button
  const genBtn = document.getElementById('genReportBtn');
  if (genBtn) {
    genBtn.disabled = false;
    genBtn.style.opacity = '1';
  }
}

// Generate the selected report format
async function generateSelectedReport() {
  if (!selectedFormat) return;

  const btn = document.getElementById('genReportBtn');
  const originalText = btn ? btn.textContent : 'Generate Report';
  if (btn) {
    btn.textContent = 'Generating...';
    btn.disabled = true;
  }

  try {
    if (selectedFormat === 'json') {
      await generateJSONReport();
    } else if (selectedFormat === 'pdf') {
      await generatePDFReport();
    }
    closeReportModal();
    showNotification('Report generated successfully!', 'success');
  } catch (error) {
    console.error('Report generation error:', error);
    showNotification('Failed to generate report: ' + error.message, 'error');
  } finally {
    if (btn) {
      btn.textContent = originalText;
      btn.disabled = false;
    }
  }
}

// Generate JSON report
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
    fileAnalysis: fileData,
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

// Generate PDF report using jsPDF
async function generatePDFReport() {
  const { jsPDF } = window.jspdf;
  if (!jsPDF) {
    throw new Error('PDF library not loaded');
  }
  
  const doc = new jsPDF();

  const fileData = JSON.parse(sessionStorage.getItem('analysisResults') || '[]');
  const urlData = JSON.parse(sessionStorage.getItem('urlResults') || '[]');
  const chartData = calculateReportChartData();

  // Colors
  const primaryColor = [0, 212, 255];
  const greenColor = [0, 255, 65];
  const redColor = [220, 20, 60];
  const yellowColor = [255, 107, 53];

  // Header
  doc.setFillColor(10, 10, 10);
  doc.rect(0, 0, 210, 40, 'F');

  doc.setTextColor(...primaryColor);
  doc.setFontSize(24);
  doc.setFont('helvetica', 'bold');
  doc.text('ZeroRisk Sentinel', 20, 25);

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'normal');
  doc.text('Security Analysis Report', 20, 33);

  // Report info
  doc.setTextColor(100, 100, 100);
  doc.setFontSize(10);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 50);
  doc.text(`Report ID: ZRS-${Date.now().toString(36).toUpperCase()}`, 20, 56);

  // Executive Summary Section
  doc.setTextColor(...primaryColor);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.text('Executive Summary', 20, 75);

  doc.setDrawColor(...primaryColor);
  doc.setLineWidth(0.5);
  doc.line(20, 78, 190, 78);

  // Summary stats
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');

  let yPos = 88;
  doc.text(`Total Files Analyzed: ${fileData.length}`, 25, yPos);
  yPos += 7;
  doc.text(`Total URLs Analyzed: ${urlData.length}`, 25, yPos);
  yPos += 7;
  doc.text(`Overall Security Score: ${chartData.avgScore}/100`, 25, yPos);
  yPos += 7;

  // Threat level color
  let threatColor = greenColor;
  let threatText = 'LOW RISK';
  if (chartData.avgScore < 40) {
    threatColor = redColor;
    threatText = 'CRITICAL RISK';
  } else if (chartData.avgScore < 70) {
    threatColor = yellowColor;
    threatText = 'MODERATE RISK';
  }

  doc.setTextColor(...threatColor);
  doc.setFont('helvetica', 'bold');
  doc.text(`Threat Level: ${threatText}`, 25, yPos);
  yPos += 15;

  // Threat Distribution
  doc.setTextColor(...primaryColor);
  doc.setFontSize(16);
  doc.text('Threat Distribution', 20, yPos);
  yPos += 3;
  doc.line(20, yPos, 190, yPos);
  yPos += 10;

  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');

  doc.setTextColor(0, 255, 65);
  doc.text(`Safe: ${chartData.safe}`, 25, yPos);
  yPos += 7;

  doc.setTextColor(255, 107, 53);
  doc.text(`Warnings: ${chartData.warning}`, 25, yPos);
  yPos += 7;

  doc.setTextColor(220, 20, 60);
  doc.text(`Critical Threats: ${chartData.critical}`, 25, yPos);
  yPos += 15;

  // File Analysis Details
  if (fileData.length > 0) {
    doc.setTextColor(...primaryColor);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text('File Analysis Details', 20, yPos);
    yPos += 3;
    doc.line(20, yPos, 190, yPos);
    yPos += 10;

    fileData.forEach((file, index) => {
      // Check if we need a new page
      if (yPos > 270) {
        doc.addPage();
        yPos = 20;
      }

      doc.setTextColor(255, 255, 255);
      doc.setFontSize(12);
      doc.setFont('helvetica', 'bold');
      doc.text(`${index + 1}. ${file.name || 'Unknown'}`, 25, yPos);
      yPos += 7;

      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');

      // Threat level with color
      let fileThreatColor = greenColor;
      if (file.threatLevel === 'critical' || file.threatLevel === 'high') {
        fileThreatColor = redColor;
      } else if (file.threatLevel === 'medium') {
        fileThreatColor = yellowColor;
      }

      doc.setTextColor(...fileThreatColor);
      doc.text(`Threat Level: ${(file.threatLevel || 'unknown').toUpperCase()}`, 30, yPos);
      yPos += 5;

      doc.setTextColor(200, 200, 200);
      doc.text(`Threat Score: ${file.threatScore || 0}/100`, 30, yPos);
      yPos += 5;

      if (file.size) {
        const sizeKB = (file.size / 1024).toFixed(2);
        doc.text(`Size: ${sizeKB} KB`, 30, yPos);
        yPos += 5;
      }

      // Findings
      if (file.findings && file.findings.length > 0) {
        doc.setTextColor(255, 107, 53);
        doc.text('Findings:', 30, yPos);
        yPos += 5;

        file.findings.forEach(finding => {
          if (yPos > 280) {
            doc.addPage();
            yPos = 20;
          }
          doc.setTextColor(200, 200, 200);
          const findingText = finding.description || finding;
          doc.text(`- ${findingText.substring(0, 75)}${findingText.length > 75 ? '...' : ''}`, 35, yPos);
          yPos += 4;
        });
      }

      yPos += 8;
    });
  }

  // URL Analysis Details
  if (urlData.length > 0) {
    if (yPos > 240) {
      doc.addPage();
      yPos = 20;
    }

    doc.setTextColor(...primaryColor);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text('URL Analysis Details', 20, yPos);
    yPos += 3;
    doc.line(20, yPos, 190, yPos);
    yPos += 10;

    urlData.forEach((url, index) => {
      if (yPos > 270) {
        doc.addPage();
        yPos = 20;
      }

      doc.setTextColor(255, 255, 255);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      const urlText = (url.url || '').substring(0, 70) + ((url.url || '').length > 70 ? '...' : '');
      doc.text(`${index + 1}. ${urlText}`, 25, yPos);
      yPos += 6;

      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');

      let urlThreatColor = greenColor;
      if (url.threatLevel === 'critical' || url.threatLevel === 'high') {
        urlThreatColor = redColor;
      } else if (url.threatLevel === 'medium') {
        urlThreatColor = yellowColor;
      }

      doc.setTextColor(...urlThreatColor);
      doc.text(`Threat Level: ${(url.threatLevel || 'unknown').toUpperCase()} | Score: ${url.threatScore || 0}/100`, 30, yPos);
      yPos += 5;

      if (url.findings && url.findings.length > 0) {
        doc.setTextColor(200, 200, 200);
        doc.text('Indicators:', 30, yPos);
        yPos += 5;

        url.findings.forEach(finding => {
          if (yPos > 280) {
            doc.addPage();
            yPos = 20;
          }
          const findingStr = String(finding).substring(0, 75) + (String(finding).length > 75 ? '...' : '');
          doc.text(`- ${findingStr}`, 35, yPos);
          yPos += 4;
        });
      }

      yPos += 8;
    });
  }

  // Footer on each page
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFillColor(10, 10, 10);
    doc.rect(0, 287, 210, 10, 'F');
    doc.setTextColor(100, 100, 100);
    doc.setFontSize(8);
    doc.text(`ZeroRisk Sentinel v2.1 | Page ${i} of ${pageCount}`, 105, 293, { align: 'center' });
    doc.text('Confidential Security Report', 190, 293, { align: 'right' });
  }

  // Save
  doc.save(`zerorisk-report-${new Date().toISOString().split('T')[0]}.pdf`);
}
//  END REPORT GENERATION 