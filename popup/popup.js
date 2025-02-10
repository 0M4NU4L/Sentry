document.addEventListener('DOMContentLoaded', async () => {
  const warningContainer = document.getElementById('warning-container');
  const detailsList = document.getElementById('detection-details');
  const proceedButton = document.getElementById('proceed-button');
  const leaveButton = document.getElementById('leave-button');
  const historyList = document.getElementById('detection-history');

  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  // Get detection data from background service worker
  chrome.runtime.sendMessage({ type: 'GET_DETECTION_DATA', url: tab.url }, (response) => {
    if (response && response.detected) {
      displayWarning(response.data);
      updateDetectionHistory();
    } else {
      displaySafeStatus();
    }
  });

  function displayWarning(data) {
    warningContainer.classList.add('warning');
    
    // Create risk score indicator
    const riskScore = document.createElement('div');
    riskScore.className = 'risk-score';
    riskScore.innerHTML = `
      <h2>Risk Score: ${data.riskScore}%</h2>
      <div class="progress-bar">
        <div class="progress" style="width: ${data.riskScore}%"></div>
      </div>
    `;
    
    // Display detected flags
    const flagsList = document.createElement('ul');
    data.flags.forEach(flag => {
      const li = document.createElement('li');
      li.textContent = formatFlagText(flag);
      flagsList.appendChild(li);
    });
    
    detailsList.appendChild(riskScore);
    detailsList.appendChild(flagsList);
  }

  function displaySafeStatus() {
    warningContainer.classList.add('safe');
    detailsList.innerHTML = `
      <div class="safe-status">
        <h2>✓ No Phishing Detected</h2>
        <p>This website appears to be safe.</p>
      </div>
    `;
  }

  function formatFlagText(flag) {
    const flagMessages = {
      'suspiciousUrl': 'Suspicious URL pattern detected',
      'suspiciousContent': 'Suspicious content or wording found',
      'hasSensitiveInputs': 'Contains sensitive input fields',
      'tooManySensitiveInputs': 'Unusual number of sensitive input fields'
    };
    return flagMessages[flag] || flag;
  }

  async function updateDetectionHistory() {
    // Get recent detections from service worker
    chrome.runtime.sendMessage({ type: 'GET_RECENT_DETECTIONS' }, (detections) => {
      if (detections && detections.length > 0) {
        const historyHTML = detections
          .map(d => `
            <div class="history-item">
              <div class="site-info">
                <span class="risk-label">${d.riskScore}%</span>
                <span class="site-url">${truncateUrl(d.url)}</span>
              </div>
              <span class="detection-time">${formatTime(d.timestamp)}</span>
            </div>
          `)
          .join('');
        historyList.innerHTML = historyHTML;
      } else {
        historyList.innerHTML = '<p class="no-history">No recent detections</p>';
      }
    });
  }

  function truncateUrl(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname + (urlObj.pathname.length > 1 ? '/...' : '');
    } catch {
      return url.substring(0, 50) + '...';
    }
  }

  function formatTime(timestamp) {
    const minutes = Math.floor((Date.now() - timestamp) / 60000);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    return new Date(timestamp).toLocaleDateString();
  }

  // Button event listeners
  proceedButton.addEventListener('click', () => {
    chrome.runtime.sendMessage({ 
      type: 'USER_PROCEED', 
      url: tab.url 
    });
    window.close();
  });

  leaveButton.addEventListener('click', () => {
    chrome.tabs.remove(tab.id);
    window.close();
  });
});
