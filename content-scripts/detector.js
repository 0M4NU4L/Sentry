// Remove the import statement since content scripts can't use ES6 modules
// Instead, we'll make the functions available globally

function createWarningBanner(details) {
  const banner = document.createElement('div');
  banner.id = 'phish-alert-banner';
  banner.innerHTML = `
    <h2>⚠️ Warning: Potential Phishing Site Detected!</h2>
    <p>${details.message}</p>
    <button id="close-warning">Proceed Anyway</button>
  `;
  document.body.prepend(banner);
  
  document.getElementById('close-warning').onclick = () => banner.remove();
}

function extractPageFeatures() {
  return {
    url: window.location.href,
    content: document.body.innerText,
    forms: Array.from(document.forms).map(form => ({
      action: form.action,
      inputs: Array.from(form.querySelectorAll('input')).map(input => input.type || input.name || '')
    })),
    domain: window.location.hostname
  };
}

// Add message listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkPhishing") {
    analyzePageForPhishing();
  }
});

function analyzePageForPhishing() {
  const features = extractPageFeatures();
  
  const results = {
    suspiciousUrl: hasSuspiciousURL(features.url) || window.PHISHING_RULES.analyzeUrl(features.url),
    suspiciousContent: window.PHISHING_RULES.analyzeContent(features.content),
    formAnalysis: window.PHISHING_RULES.analyzeForms(features.forms),
    suspiciousDomain: hasSuspiciousDomain(features.url),
    hasUnsecureLogin: hasLoginForm()
  };
  
  const riskScore = calculateRiskScore(results);
  
  // Lower threshold and include more checks
  if (riskScore > 20 || results.suspiciousDomain || results.hasUnsecureLogin) {
    createWarningBanner({
      message: `This website shows signs of being a phishing attempt (Risk Score: ${riskScore}%)`
    });
    
    // Notify background script
    chrome.runtime.sendMessage({
      type: 'PHISHING_DETECTED',
      data: {
        url: features.url,
        riskScore,
        flags: Object.entries(results)
          .filter(([_, value]) => 
            value === true || (typeof value === 'object' && value.hasSensitiveInputs)
          )
          .map(([key]) => key)
      }
    });
  }
}

// Update risk score calculation
function calculateRiskScore(results) {
  const weights = {
    suspiciousUrl: 30,
    suspiciousContent: 25,
    suspiciousDomain: 25,
    hasUnsecureLogin: 20,
    hasSensitiveInputs: 15,
    tooManySensitiveInputs: 15
  };
  
  let score = 0;
  if (results.suspiciousUrl) score += weights.suspiciousUrl;
  if (results.suspiciousContent) score += weights.suspiciousContent;
  if (results.suspiciousDomain) score += weights.suspiciousDomain;
  if (results.hasUnsecureLogin) score += weights.hasUnsecureLogin;
  if (results.formAnalysis.hasSensitiveInputs) score += weights.hasSensitiveInputs;
  if (results.formAnalysis.tooManySensitiveInputs) score += weights.tooManySensitiveInputs;
  
  return Math.min(100, score); // Cap at 100%
}

// Run analysis when page loads
analyzePageForPhishing();

// Also run when content changes significantly
const observer = new MutationObserver(debounce(() => {
  analyzePageForPhishing();
}, 1000));

observer.observe(document.body, {
  childList: true,
  subtree: true
});

function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}