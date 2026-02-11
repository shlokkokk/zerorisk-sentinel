const BACKEND_URL = 'https://zerorisk-sentinel-backend.onrender.com';
const BACKEND_TIMEOUT = 25000; // 15 seconds

// Main analyze function with timeout and fallback
async function analyzeURL() {
    const input = document.getElementById("urlInput");
    const url = input.value.trim();
    
    if (!url) {
        alert("Enter a URL to analyze");
        return;
    }
    
    // Show progress
    document.getElementById("scanningProgress").classList.remove("hidden");
    const progressFill = document.getElementById("progressFill");
    const progressText = document.getElementById("progressText");
    const currentFile = document.getElementById("currentFile");
    
    const steps = [
        "Connecting to backend...",
        "Checking threat intelligence databases...",
        "Analyzing DNS and SSL...",
        "Compiling results..."
    ];
    
    // Animate progress
    let step = 0;
    const progressInterval = setInterval(() => {
        if (step < steps.length) {
            currentFile.textContent = steps[step];
            progressFill.style.width = Math.round(((step + 1) / steps.length) * 75) + "%";
            progressText.textContent = Math.round(((step + 1) / steps.length) * 75) + "%";
            step++;
        }
    }, 1000);
    
    // Try backend with timeout
    const backendPromise = fetch(`${BACKEND_URL}/api/analyze-url`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url: url})
    });
    
    const timeoutPromise = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Timeout')), BACKEND_TIMEOUT)
    );
    
    try {
        const response = await Promise.race([backendPromise, timeoutPromise]);
        clearInterval(progressInterval);
        
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error);
        }
        
        // Backend success!
        progressFill.style.width = "100%";
        progressText.textContent = "100%";
        currentFile.textContent = "Backend analysis complete!";
        
        // Small delay to show completion
        await new Promise(r => setTimeout(r, 500));
        
        document.getElementById("scanningProgress").classList.add("hidden");
        sessionStorage.setItem("urlResults", JSON.stringify([data.data]));
        window.location.href = "results.html";
        
    } catch (err) {
        // Backend failed or timeout - use local
        clearInterval(progressInterval);
        console.log("Backend unavailable, using local heuristics:", err.message);
        
        currentFile.textContent = "Backend timeout - switching to local analysis...";
        await new Promise(r => setTimeout(r, 800));
        
        document.getElementById("scanningProgress").classList.add("hidden");
        performLocalURLAnalysis(url);
    }
}

// Local heuristic analysis (fallback)
function performLocalURLAnalysis(url) {
    let parsed, hostname, score = 0, findings = [];
    
    try {
        parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
        hostname = parsed.hostname.toLowerCase();
    } catch(e) {
        alert("Invalid URL format");
        return;
    }
    
    // IP check
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        score += 30;
        findings.push({description: "Uses raw IP address instead of domain", severity: "high"});
    }
    
    // Shorteners
    if (/bit\.ly|tinyurl|t\.co|ow\.ly|cutt\.ly|rb\.gy/i.test(url)) {
        score += 25;
        findings.push({description: "URL shortener hides final destination", severity: "high"});
    }
    
    // Phishing keywords
    if (/login|verify|secure|bank|password|account|update|confirm|urgent/i.test(url)) {
        score += 20;
        findings.push({description: "Contains phishing-related keywords", severity: "medium"});
    }
    
    // Risky TLDs
    if (/\.(xyz|tk|ml|ga|cf|top|icu)$/i.test(url)) {
        score += 20;
        findings.push({description: "Uses high-risk TLD", severity: "medium"});
    }
    
    // No HTTPS
    if (!url.startsWith('https')) {
        score += 15;
        findings.push({description: "Connection not encrypted (no HTTPS)", severity: "medium"});
    }
    
    // Deep path
    if (parsed.pathname.split('/').length > 5) {
        score += 10;
        findings.push({description: "Unusually deep URL path", severity: "low"});
    }
    
    // Long URL
    if (url.length > 100) {
        score += 5;
        findings.push({description: "Unusually long URL", severity: "low"});
    }
    
    score = Math.min(score, 100);
    let level = score >= 70 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : score > 0 ? 'low' : 'safe';
    
    const result = {
        url: url,
        domain: hostname,
        threat_score: score,
        threat_level: level,
        findings: findings,
        explanation: generateLocalExplanation(findings, level, url),
        services: {note: "Local heuristic analysis - backend unavailable"},
        backend_based: false, // Flag for UI
        scan_time: new Date().toISOString()
    };
    
    sessionStorage.setItem("urlResults", JSON.stringify([result]));
    window.location.href = "results.html";
}

function generateLocalExplanation(findings, level, url) {
    const map = {
        safe: "No significant threats detected via local heuristics.",
        low: "Minor suspicious patterns detected.",
        medium: "Multiple suspicious indicators present.",
        high: "Strong correlation with malicious behavior.",
        critical: "High-confidence malicious indicators detected."
    };
    
    let text = `Local analysis of "${url}":\n\n`;
    findings.forEach(f => {
        text += `• ${f.description}\n`;
    });
    text += `\n${map[level]} (Local analysis - backend unavailable)`;
    return text;
}
// Toggle between Live and Demo mode
function setScanMode(mode) {
    const liveBtn = document.getElementById('liveModeBtn');
    const demoBtn = document.getElementById('demoModeBtn');
    const demoUrlsSection = document.getElementById('demoUrls');
    
    if (mode === 'live') {
        // Live mode active
        liveBtn.className = 'px-4 py-2 rounded-lg bg-blue-600 text-white font-medium';
        demoBtn.className = 'px-4 py-2 rounded-lg bg-gray-700 text-gray-300 font-medium hover:bg-gray-600';
        demoUrlsSection.classList.add('hidden');
    } else {
        // Demo mode active
        demoBtn.className = 'px-4 py-2 rounded-lg bg-blue-600 text-white font-medium';
        liveBtn.className = 'px-4 py-2 rounded-lg bg-gray-700 text-gray-300 font-medium hover:bg-gray-600';
        demoUrlsSection.classList.remove('hidden');
    }
}
function runDemoURL(demoTypeOrUrl) {
    const input = document.getElementById("urlInput");
    if (!input) return;

    // Demo URL database - for when a key is passed
    const demoURLs = {
        'google-phish': 'https://secure-google-login.xyz/verify?token=abc123&session=fake',
        'paypal-phish': 'http://paypal-alerts-login.com/secure/verify/account',
        'ip-suspicious': 'http://192.168.0.1/auth/login.php?redirect=evil',
        'shortener': 'https://bit.ly/3xAmPlE',
        'mixed-signals': 'http://amazon-security-verify.tk/login?urgent=true'
    };

    // Check if it's a key in demoURLs or already a full URL
    const url = demoURLs[demoTypeOrUrl] || demoTypeOrUrl;
    
    if (!url) return;

    input.value = url;
    analyzeURL();
}
