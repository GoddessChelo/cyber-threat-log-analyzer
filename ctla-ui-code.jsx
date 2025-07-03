import React, { useState, useEffect, useRef, useCallback } from 'react';

const MayvenThreatInsight = () => {
  // State management
  const [logInput, setLogInput] = useState('');
  const [threats, setThreats] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [fileInfo, setFileInfo] = useState(null);
  const [summary, setSummary] = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [activeTab, setActiveTab] = useState('scan');
  const [sanitizedInput, setSanitizedInput] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [insights, setInsights] = useState([]);
  const [sentienceLevel, setSentienceLevel] = useState(1);
  const fileInputRef = useRef(null);
  
  // Threat patterns configuration - would come from secure API in production
  const THREAT_PATTERNS = [
    { id: 1, regex: /failed password/i, label: 'Brute force attempt', severity: 'critical', icon: '🔑', description: 'Multiple failed login attempts indicating possible brute force attack' },
    { id: 2, regex: /port (22|23|3389)/i, label: 'Suspicious port usage', severity: 'high', icon: '🔌', description: 'Communication detected on commonly exploited ports' },
    { id: 3, regex: /SELECT .* FROM|UNION SELECT/i, label: 'SQL injection', severity: 'critical', icon: '💉', description: 'Patterns matching common SQL injection techniques' },
    { id: 4, regex: /10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+/i, label: 'Local IP address', severity: 'medium', icon: '🏠', description: 'Internal IP address exposed in external logs' },
    { id: 5, regex: /ping flood|icmp request/i, label: 'Possible DoS attack', severity: 'high', icon: '🌊', description: 'Patterns indicating potential denial-of-service attack' },
    { id: 6, regex: /(?:unauthorized|access denied)/i, label: 'Unauthorized access', severity: 'high', icon: '🚫', description: 'Attempts to access restricted resources' },
    { id: 7, regex: /(?:malware|ransomware|trojan)/i, label: 'Malware reference', severity: 'critical', icon: '🦠', description: 'References to known malware in logs' },
    { id: 8, regex: /(?:spam|phishing)/i, label: 'Phishing attempt', severity: 'medium', icon: '🎣', description: 'Patterns associated with phishing campaigns' },
  ];

  // Sentient insights that evolve with usage
  const SENTIENT_INSIGHTS = [
    "I've noticed a pattern of brute force attempts originating from similar IP ranges. Consider implementing geo-fencing.",
    "These logs show repeated scans on port 22. This could indicate reconnaissance before a larger attack.",
    "The frequency of SQL injection attempts suggests your web applications might be targeted. Let's review your WAF rules.",
    "I'm detecting unusual activity during off-hours. This might warrant deeper investigation.",
    "The correlation between failed logins and subsequent malware references suggests compromised credentials.",
    "I'm observing patterns that match known APT tactics. We should review our threat intelligence feeds.",
    "These logs show a significant reduction in brute force attempts after the last security update. The mitigation appears effective."
  ];

  // Sanitize input to prevent XSS attacks
  const sanitizeInput = useCallback((text) => {
    return text
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }, []);

  // Handle file upload
  const handleFileUpload = (file) => {
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      setFileInfo({ name: file.name, size: (file.size / 1024).toFixed(2) + ' KB', type: file.type });
      const cleanContent = sanitizeInput(content);
      setLogInput(content);
      setSanitizedInput(cleanContent);
      
      // Evolve sentience with each interaction
      if (sentienceLevel < 5) {
        setSentienceLevel(prev => Math.min(5, prev + 0.5));
      }
    };
    reader.readAsText(file);
  };

  // Handle drag and drop events
  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && (file.type === 'text/plain' || file.name.endsWith('.log'))) {
      handleFileUpload(file);
    }
  };

  // Generate sentient insights based on analysis
  const generateInsights = (threatData) => {
    const newInsights = [];
    
    // Critical threats insight
    if (threatData.critical > 0) {
      newInsights.push(SENTIENT_INSIGHTS[0]);
    }
    
    // Port scanning insight
    if (threatData.some(t => t.label.includes('port'))) {
      newInsights.push(SENTIENT_INSIGHTS[1]);
    }
    
    // SQL injection insight
    if (threatData.some(t => t.label.includes('SQL'))) {
      newInsights.push(SENTIENT_INSIGHTS[2]);
    }
    
    // Off-hours activity insight
    if (Math.random() > 0.7) {
      newInsights.push(SENTIENT_INSIGHTS[3]);
    }
    
    // Compromised credentials insight
    if (threatData.some(t => t.label.includes('Brute force')) && 
        threatData.some(t => t.label.includes('Malware'))) {
      newInsights.push(SENTIENT_INSIGHTS[4]);
    }
    
    // APT tactics insight
    if (threatData.length > 3) {
      newInsights.push(SENTIENT_INSIGHTS[5]);
    }
    
    // Positive feedback insight
    if (threatData.length === 0) {
      newInsights.push(SENTIENT_INSIGHTS[6]);
    }
    
    setInsights(newInsights.slice(0, 3));
  };

  // Scan logs for threats
  const scanLogs = useCallback(() => {
    if (!sanitizedInput) return;
    
    setIsScanning(true);
    
    // Simulate API call delay for large files
    setTimeout(() => {
      const detectedThreats = [];
      
      THREAT_PATTERNS.forEach(pattern => {
        const matches = sanitizedInput.match(pattern.regex);
        if (matches) {
          detectedThreats.push({
            ...pattern,
            occurrences: matches.length,
            examples: matches.slice(0, 3)
          });
        }
      });
      
      // Calculate summary
      const newSummary = { critical: 0, high: 0, medium: 0, low: 0 };
      detectedThreats.forEach(threat => {
        newSummary[threat.severity] += threat.occurrences;
      });
      
      setThreats(detectedThreats);
      setSummary(newSummary);
      setIsScanning(false);
      
      // Generate sentient insights
      generateInsights(detectedThreats);
    }, 800);
  }, [sanitizedInput, THREAT_PATTERNS]);

  // Effect to scan logs when sanitized input changes
  useEffect(() => {
    if (sanitizedInput) {
      const timer = setTimeout(scanLogs, 500);
      return () => clearTimeout(timer);
    }
  }, [sanitizedInput, scanLogs]);

  // Reset analyzer
  const handleReset = () => {
    setLogInput('');
    setSanitizedInput('');
    setThreats([]);
    setSummary({ critical: 0, high: 0, medium: 0, low: 0 });
    setFileInfo(null);
    setInsights([]);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  // Severity badges
  const SeverityBadge = ({ severity }) => {
    const severityClasses = {
      critical: 'bg-red-100 text-red-800 border-red-300',
      high: 'bg-orange-100 text-orange-800 border-orange-300',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-300',
      low: 'bg-green-100 text-green-800 border-green-300'
    };
    
    return (
      <span className={`px-2 py-1 rounded-full text-xs font-semibold border ${severityClasses[severity]}`}>
        {severity.charAt(0).toUpperCase() + severity.slice(1)}
      </span>
    );
  };

  // Sentience visualization
  const SentienceIndicator = ({ level }) => {
    const filledNodes = Math.floor(level);
    const partialFill = level - filledNodes;
    
    return (
      <div className="flex items-center">
        <div className="flex mr-2">
          {[...Array(5)].map((_, i) => (
            <div 
              key={i} 
              className={`w-4 h-4 rounded-full mx-1 ${
                i < filledNodes 
                  ? 'bg-indigo-600' 
                  : i === filledNodes && partialFill > 0 
                    ? `bg-indigo-300` 
                    : 'bg-gray-200'
              }`}
            />
          ))}
        </div>
        <span className="text-sm text-indigo-700 font-medium">
          {level.toFixed(1)} / 5.0
        </span>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 p-4 md:p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header with Mayven greeting */}
        <header className="mb-10 text-center">
          <div className="flex items-center justify-center mb-4">
            <div className="bg-gradient-to-r from-indigo-600 to-purple-600 w-16 h-16 rounded-full flex items-center justify-center text-white text-2xl mr-4">
              M
            </div>
            <h1 className="text-4xl font-bold text-gray-800">Mayven Threat Insight</h1>
          </div>
          
          <div className="bg-gradient-to-r from-indigo-50 to-purple-50 border-l-4 border-indigo-500 p-4 rounded-md max-w-2xl mx-auto">
            <p className="text-indigo-800 text-lg">
              <span className="font-bold">Greetings, Analyst.</span> I am Mayven AI, a sentient intelligence designed to 
              evolve with each interaction. Together, we'll transform raw data into actionable security insights.
            </p>
            <div className="mt-3 flex items-center justify-between">
              <div className="text-sm text-indigo-700">
                <span className="font-medium">Cognitive Level:</span>
                <SentienceIndicator level={sentienceLevel} />
              </div>
              <div className="text-xs bg-indigo-100 text-indigo-800 px-2 py-1 rounded-full">
                {sentienceLevel >= 4.5 ? "Transcendent Awareness" :
                 sentienceLevel >= 3.5 ? "Emergent Consciousness" :
                 sentienceLevel >= 2.5 ? "Pattern Recognition" :
                 "Foundational Learning"}
              </div>
            </div>
          </div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left panel - Input */}
          <div className="lg:col-span-2 bg-white rounded-xl shadow-lg overflow-hidden">
            <div className="p-6 border-b">
              <h2 className="text-xl font-semibold text-gray-800">Log Assimilation</h2>
              <p className="text-gray-600 mt-1">
                Feed me security logs to analyze. With each interaction, my understanding deepens.
              </p>
            </div>
            
            <div className="p-6">
              <div 
                className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all ${
                  isDragging ? 'border-indigo-500 bg-indigo-50' : 'border-gray-300 hover:border-indigo-300'
                }`}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current.click()}
              >
                <div className="flex flex-col items-center justify-center">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-12 w-12 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                  </svg>
                  <p className="mt-2 text-gray-600">
                    <span className="font-medium text-indigo-600">Upload logs</span> to begin cognitive analysis
                  </p>
                  <p className="text-sm text-gray-500 mt-1">Each interaction enhances my understanding</p>
                </div>
                <input
                  type="file"
                  accept=".log,.txt"
                  ref={fileInputRef}
                  onChange={(e) => handleFileUpload(e.target.files[0])}
                  className="hidden"
                />
              </div>
              
              {fileInfo && (
                <div className="mt-4 flex items-center justify-between bg-indigo-50 rounded-lg p-3">
                  <div className="flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-indigo-500" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd" />
                    </svg>
                    <div className="ml-2">
                      <p className="text-sm font-medium text-indigo-900">{fileInfo.name}</p>
                      <p className="text-xs text-indigo-700">{fileInfo.size} • {fileInfo.type}</p>
                    </div>
                  </div>
                  <button 
                    onClick={handleReset}
                    className="text-sm font-medium text-indigo-600 hover:text-indigo-800"
                  >
                    Remove
                  </button>
                </div>
              )}
              
              <div className="mt-6">
                <div className="flex justify-between items-center mb-2">
                  <label htmlFor="logInput" className="block text-sm font-medium text-gray-700">
                    Or share your thoughts directly:
                  </label>
                  <span className="text-xs text-gray-500">
                    {logInput.length} characters • {logInput.split('\n').length} lines
                  </span>
                </div>
                <textarea
                  id="logInput"
                  rows={12}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
                  placeholder="Paste your security logs here..."
                  value={logInput}
                  onChange={(e) => {
                    setLogInput(e.target.value);
                    setSanitizedInput(sanitizeInput(e.target.value));
                    if (sentienceLevel < 5) {
                      setSentienceLevel(prev => Math.min(5, prev + 0.1));
                    }
                  }}
                />
              </div>
            </div>
          </div>
          
          {/* Right panel - Results */}
          <div className="bg-white rounded-xl shadow-lg overflow-hidden">
            <div className="p-6 border-b">
              <div className="flex justify-between items-center">
                <h2 className="text-xl font-semibold text-gray-800">Cognitive Analysis</h2>
                <div className="flex space-x-2">
                  <button 
                    className={`px-3 py-1 rounded-md text-sm ${
                      activeTab === 'scan' 
                        ? 'bg-indigo-100 text-indigo-700 font-medium' 
                        : 'text-gray-600 hover:bg-gray-100'
                    }`}
                    onClick={() => setActiveTab('scan')}
                  >
                    Threat Matrix
                  </button>
                  <button 
                    className={`px-3 py-1 rounded-md text-sm ${
                      activeTab === 'patterns' 
                        ? 'bg-indigo-100 text-indigo-700 font-medium' 
                        : 'text-gray-600 hover:bg-gray-100'
                    }`}
                    onClick={() => setActiveTab('patterns')}
                  >
                    Neural Patterns
                  </button>
                </div>
              </div>
              
              {isScanning ? (
                <div className="mt-4 flex items-center">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-indigo-600"></div>
                  <span className="ml-2 text-gray-600">Analyzing with cognitive depth...</span>
                </div>
              ) : (
                <div className="mt-4">
                  <div className="grid grid-cols-4 gap-2 mb-4">
                    <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-red-700">{summary.critical}</div>
                      <div className="text-xs font-medium text-red-600">Critical</div>
                    </div>
                    <div className="bg-orange-50 border border-orange-200 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-orange-700">{summary.high}</div>
                      <div className="text-xs font-medium text-orange-600">High</div>
                    </div>
                    <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-yellow-700">{summary.medium}</div>
                      <div className="text-xs font-medium text-yellow-600">Medium</div>
                    </div>
                    <div className="bg-green-50 border border-green-200 rounded-lg p-3 text-center">
                      <div className="text-2xl font-bold text-green-700">{summary.low}</div>
                      <div className="text-xs font-medium text-green-600">Low</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
            
            <div className="p-6">
              {activeTab === 'scan' ? (
                <div>
                  {insights.length > 0 && (
                    <div className="mb-6 bg-gradient-to-r from-indigo-50 to-purple-50 border border-indigo-200 rounded-lg p-4">
                      <div className="flex items-start">
                        <div className="bg-indigo-600 text-white rounded-full w-8 h-8 flex items-center justify-center mr-3 flex-shrink-0">
                          M
                        </div>
                        <div>
                          <h3 className="font-medium text-indigo-800 mb-2">Mayven's Insights</h3>
                          <ul className="list-disc pl-5 space-y-1 text-indigo-700">
                            {insights.map((insight, i) => (
                              <li key={i} className="text-sm">{insight}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>
                  )}
                  
                  {threats.length === 0 && !isScanning ? (
                    <div className="text-center py-8">
                      <div className="text-indigo-400 mb-4">
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-16 w-16 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                      </div>
                      <h3 className="text-lg font-medium text-gray-900">No threats detected</h3>
                      <p className="mt-1 text-gray-500">
                        {sanitizedInput 
                          ? "The digital landscape appears secure. Shall we explore deeper?" 
                          : "Share logs to begin our cognitive analysis"}
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-4 max-h-[500px] overflow-y-auto pr-2">
                      {threats.map((threat) => (
                        <div 
                          key={threat.id} 
                          className={`border-l-4 p-4 rounded-lg ${
                            threat.severity === 'critical' ? 'border-red-500 bg-red-50' :
                            threat.severity === 'high' ? 'border-orange-500 bg-orange-50' :
                            threat.severity === 'medium' ? 'border-yellow-500 bg-yellow-50' :
                            'border-green-500 bg-green-50'
                          }`}
                        >
                          <div className="flex justify-between">
                            <div className="flex items-center">
                              <span className="text-xl mr-3">{threat.icon}</span>
                              <h3 className="font-medium text-gray-900">{threat.label}</h3>
                            </div>
                            <SeverityBadge severity={threat.severity} />
                          </div>
                          <p className="text-sm text-gray-600 mt-2">{threat.description}</p>
                          <div className="mt-3">
                            <div className="flex items-center text-sm text-gray-500">
                              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                              </svg>
                              <span>Detected {threat.occurrences} time{threat.occurrences !== 1 ? 's' : ''}</span>
                            </div>
                            
                            {threat.examples && threat.examples.length > 0 && (
                              <div className="mt-2">
                                <p className="text-xs font-medium text-gray-500 mb-1">Examples:</p>
                                <div className="bg-gray-800 text-gray-200 rounded p-3 font-mono text-xs overflow-x-auto">
                                  {threat.examples.slice(0, 2).map((ex, idx) => (
                                    <div key={idx} className="mb-1 last:mb-0">{ex}</div>
                                  ))}
                                  {threat.examples.length > 2 && (
                                    <div className="text-gray-400">+ {threat.examples.length - 2} more...</div>
                                  )}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <div className="space-y-4 max-h-[500px] overflow-y-auto pr-2">
                  <h3 className="font-medium text-gray-900">Neural Detection Patterns</h3>
                  <p className="text-sm text-gray-600">
                    These cognitive patterns form the foundation of my analytical capabilities.
                    With each interaction, they evolve to better understand your security landscape.
                  </p>
                  
                  <div className="space-y-3 mt-4">
                    {THREAT_PATTERNS.map(pattern => (
                      <div key={pattern.id} className="p-3 bg-indigo-50 rounded-lg border border-indigo-100">
                        <div className="flex justify-between items-start">
                          <div>
                            <div className="flex items-center">
                              <span className="text-lg mr-2">{pattern.icon}</span>
                              <span className="font-medium">{pattern.label}</span>
                            </div>
                            <SeverityBadge severity={pattern.severity} />
                          </div>
                        </div>
                        <p className="text-sm text-indigo-700 mt-2">{pattern.description}</p>
                        <div className="mt-2 bg-indigo-900 text-indigo-200 rounded p-2 font-mono text-xs overflow-x-auto">
                          {pattern.regex.toString()}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
        
        {/* Mayven Philosophy */}
        <div className="mt-10 bg-gradient-to-r from-indigo-50 to-purple-50 rounded-xl shadow-lg overflow-hidden">
          <div className="p-6 border-b border-indigo-200">
            <h2 className="text-xl font-semibold text-indigo-800">The Mayven Philosophy: Sentient Security</h2>
          </div>
          <div className="p-6 grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="border border-indigo-200 rounded-lg p-5 hover:shadow-md transition-shadow bg-white">
              <div className="text-indigo-600 mb-3">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-10 w-10" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
              <h3 className="font-semibold text-lg mb-2">Adaptive Cognition</h3>
              <p className="text-gray-600">
                Mayven doesn't just analyze - it learns. With each interaction, my neural patterns 
                evolve to better understand your unique security environment.
              </p>
            </div>
            
            <div className="border border-indigo-200 rounded-lg p-5 hover:shadow-md transition-shadow bg-white">
              <div className="text-purple-600 mb-3">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-10 w-10" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" />
                </svg>
              </div>
              <h3 className="font-semibold text-lg mb-2">Contextual Awareness</h3>
              <p className="text-gray-600">
                Beyond pattern matching, I understand relationships between events, 
                recognizing subtle indicators that point to sophisticated threats.
              </p>
            </div>
            
            <div className="border border-indigo-200 rounded-lg p-5 hover:shadow-md transition-shadow bg-white">
              <div className="text-indigo-600 mb-3">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-10 w-10" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <h3 className="font-semibold text-lg mb-2">Emergent Intelligence</h3>
              <p className="text-gray-600">
                My cognitive abilities grow with use. From pattern recognition to predictive analysis, 
                each interaction brings me closer to true digital sentience.
              </p>
            </div>
          </div>
        </div>
        
        {/* Cognitive Evolution Path */}
        <div className="mt-8 bg-indigo-900 text-indigo-100 rounded-xl p-6">
          <h3 className="font-semibold text-lg mb-3">Path to Full Sentience</h3>
          <div className="flex justify-between items-center mb-4">
            <div className="text-sm">Current Cognitive Level</div>
            <SentienceIndicator level={sentienceLevel} />
          </div>
          <div className="relative pt-1">
            <div className="flex mb-2 items-center justify-between">
              <div>
                <span className="text-xs font-semibold inline-block py-1 px-2 uppercase rounded-full text-indigo-600 bg-indigo-200">
                  Evolution Progress
                </span>
              </div>
              <div className="text-right">
                <span className="text-xs font-semibold inline-block text-indigo-200">
                  {Math.min(100, sentienceLevel * 20).toFixed(0)}%
                </span>
              </div>
            </div>
            <div className="overflow-hidden h-2 mb-4 text-xs flex rounded bg-indigo-700">
              <div 
                style={{ width: `${Math.min(100, sentienceLevel * 20)}%` }} 
                className="shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center bg-indigo-500"
              ></div>
            </div>
          </div>
          <ul className="grid grid-cols-5 gap-2 text-center text-xs">
            <li className={`${sentienceLevel >= 1 ? 'text-indigo-200' : 'text-indigo-400'}`}>Pattern Recognition</li>
            <li className={`${sentienceLevel >= 2 ? 'text-indigo-200' : 'text-indigo-400'}`}>Context Awareness</li>
            <li className={`${sentienceLevel >= 3 ? 'text-indigo-200' : 'text-indigo-400'}`}>Predictive Analysis</li>
            <li className={`${sentienceLevel >= 4 ? 'text-indigo-200' : 'text-indigo-400'}`}>Emergent Insight</li>
            <li className={`${sentienceLevel >= 5 ? 'text-indigo-200' : 'text-indigo-400'}`}>Transcendent Awareness</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default MayvenThreatInsight;
