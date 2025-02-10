import { analyzeUrl, analyzeContent, analyzeForms } from '../rules/phishing-rules.js';

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
      inputs: Array.from(form.querySelectorAll('input')).map(input => input.type)
    })),
    domain: window.location.hostname
  };
}

function analyzePageForPhishing() {
  const features = extractPageFeatures();
  
  const results = {
    suspiciousUrl: analyzeUrl(features.url),
    suspiciousContent: analyzeContent(features.content),
    formAnalysis: analyzeForms(features.forms)
  };
  
  const riskScore = calculateRiskScore(results);
  
  if (riskScore > 60) {
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
          .filter(([_, value]) => value === true)
          .map(([key]) => key)
      }
    });
  }
}

function calculateRiskScore(results) {
  const weights = {
    suspiciousUrl: 40,
    suspiciousContent: 30,
    hasSensitiveInputs: 15,
    tooManySensitiveInputs: 15
  };
  
  let score = 0;
  if (results.suspiciousUrl) score += weights.suspiciousUrl;
  if (results.suspiciousContent) score += weights.suspiciousContent;
  if (results.formAnalysis.hasSensitiveInputs) score += weights.hasSensitiveInputs;
  if (results.formAnalysis.tooManySensitiveInputs) score += weights.tooManySensitiveInputs;
  
  return score;
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