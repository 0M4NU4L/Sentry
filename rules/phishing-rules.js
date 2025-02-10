// URL Analysis
function hasSuspiciousURL(url) {
    const patterns = [
      /https?:\/\/(\d{1,3}\.){3}\d{1,3}/, // IP address in URL
      /@/, // Contains @ symbol
      /-\w+\.\w{2,3}$/, // Hyphen in domain
      /\.(tk|ml|ga|cf|gq)$/i // Suspicious TLDs
    ];
    return patterns.some(pattern => pattern.test(url));
  }
  
  // Domain Analysis
  function hasSuspiciousDomain(url) {
    try {
      const domain = new URL(url).hostname;
      const trustedDomains = ['paypal', 'bankofamerica', 'wellsfargo'];
      return trustedDomains.some(td => 
        domain.includes(td) && !domain.endsWith(`.${td}.com`)
      );
    } catch {
      return false;
    }
  }
  
  // Content Analysis
  function hasLoginForm() {
    return document.querySelectorAll('input[type="password"]').length > 0 &&
           !document.location.protocol.startsWith('https');
  }
  
  function hasValidSSL() {
    return document.location.protocol === 'https:';
  }
  
  function hasRedirects() {
    return window.performance
      .getEntriesByType('navigation')
      .some(entry => entry.redirectCount > 2);
  }

const PHISHING_PATTERNS = {
  // URL patterns that are suspicious
  suspiciousUrls: [
    /^(?!www\.|(?:http|ftp)s?:\/\/|[A-Za-z]:\\|\/\/).*/,
    /\.(tk|ml|ga|cf|gq|top)$/i,  // Common free domains used in phishing
    /(?:paypal|google|facebook|apple|microsoft).*\.(?!com)[a-z]{2,}/i
  ],
  
  // Content patterns that indicate phishing
  contentPatterns: [
    /(verify.*account|confirm.*identity|update.*payment)/i,
    /(?:user.*name|password).*required/i,
    /security.*(?:check|verify|confirm)/i
  ],
  
  // Form patterns that are suspicious
  formPatterns: {
    sensitiveInputs: ['password', 'credit-card', 'card-number', 'ssn'],
    maxInputs: 5  // Suspicious if more than this many sensitive inputs
  }
};

function analyzeUrl(url) {
  return PHISHING_PATTERNS.suspiciousUrls.some(pattern => pattern.test(url));
}

function analyzeContent(content) {
  return PHISHING_PATTERNS.contentPatterns.some(pattern => pattern.test(content));
}

function analyzeForms(forms) {
  let sensitiveInputCount = 0;
  
  for (const form of forms) {
    const inputs = form.inputs || [];
    sensitiveInputCount += inputs.filter(input => 
      PHISHING_PATTERNS.formPatterns.sensitiveInputs.includes(input)
    ).length;
  }
  
  return {
    hasSensitiveInputs: sensitiveInputCount > 0,
    tooManySensitiveInputs: sensitiveInputCount > PHISHING_PATTERNS.formPatterns.maxInputs
  };
}

export { analyzeUrl, analyzeContent, analyzeForms };