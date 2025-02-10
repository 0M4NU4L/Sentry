// Track detected phishing sites
let detectedPhishingSites = new Map();

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
      chrome.tabs.sendMessage(tabId, {
        action: "checkPhishing",
        url: tab.url
      });
    }
  });

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.type === 'PHISHING_DETECTED') {
    const { url, riskScore, flags } = message.data;
    
    // Store detection info
    detectedPhishingSites.set(url, {
      riskScore,
      flags,
      timestamp: Date.now()
    });
    
    // Update extension badge
    chrome.action.setBadgeText({
      text: '!',
      tabId: sender.tab.id
    });
    
    chrome.action.setBadgeBackgroundColor({
      color: '#FF0000',
      tabId: sender.tab.id
    });
  }
});

// Clean up old detections periodically
setInterval(() => {
  const oneHourAgo = Date.now() - (60 * 60 * 1000);
  for (const [url, data] of detectedPhishingSites) {
    if (data.timestamp < oneHourAgo) {
      detectedPhishingSites.delete(url);
    }
  }
}, 60 * 60 * 1000); // Run every hour

// Add these message handlers to the existing service worker

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_DETECTION_DATA') {
    const detection = detectedPhishingSites.get(message.url);
    if (detection) {
      sendResponse({
        detected: true,
        data: {
          ...detection,
          url: message.url
        }
      });
    } else {
      sendResponse({ detected: false });
    }
  }
  
  else if (message.type === 'GET_RECENT_DETECTIONS') {
    const recentDetections = Array.from(detectedPhishingSites.entries())
      .map(([url, data]) => ({
        url,
        ...data
      }))
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, 5); // Get 5 most recent
    
    sendResponse(recentDetections);
  }
  
  else if (message.type === 'USER_PROCEED') {
    // User chose to proceed - could log this for analysis
    console.log('User proceeded despite warning:', message.url);
  }
  
  return true; // Keep message channel open for async response
});