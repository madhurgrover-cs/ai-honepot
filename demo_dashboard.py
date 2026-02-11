"""
Demonstration Dashboard for Live Presentations
Shows real-time attack analysis with detailed LLM thinking and intelligence processing.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json


# Global storage for demonstration data
_demo_data = {
    "current_attack": None,
    "llm_thinking": [],
    "analysis_steps": [],
    "threat_intel": {},
    "behavioral_profile": {},
    "fingerprint_data": {},
}


def get_demo_dashboard_html() -> str:
    """Get enhanced demonstration dashboard HTML."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Honeypot - Live Demonstration</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Consolas', 'Monaco', monospace;
            background: #0a0e27;
            color: #00ff41;
            padding: 20px;
            overflow-x: hidden;
        }
        
        .container {
            max-width: 1800px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: linear-gradient(135deg, #1a1f3a 0%, #2d3561 100%);
            border-radius: 10px;
            border: 2px solid #00ff41;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
        }
        
        h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 0 10px #00ff41;
            animation: glow 2s ease-in-out infinite alternate;
        }
        
        @keyframes glow {
            from { text-shadow: 0 0 10px #00ff41, 0 0 20px #00ff41; }
            to { text-shadow: 0 0 20px #00ff41, 0 0 30px #00ff41, 0 0 40px #00ff41; }
        }
        
        .subtitle {
            font-size: 1.2em;
            color: #00d4ff;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #00ff41;
            animation: pulse 1.5s infinite;
            margin-right: 8px;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.2); }
        }
        
        .main-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .full-width {
            grid-column: 1 / -1;
        }
        
        .panel {
            background: rgba(26, 31, 58, 0.8);
            border: 2px solid #00ff41;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 0 15px rgba(0, 255, 65, 0.2);
        }
        
        .panel h2 {
            font-size: 1.5em;
            margin-bottom: 15px;
            color: #00d4ff;
            border-bottom: 2px solid #00ff41;
            padding-bottom: 10px;
        }
        
        .attack-display {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #ff0066;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            animation: slideIn 0.5s ease-out;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .attack-label {
            color: #ff0066;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .attack-value {
            color: #00ff41;
            font-size: 1.1em;
            word-break: break-all;
        }
        
        .thinking-step {
            background: rgba(0, 212, 255, 0.1);
            border-left: 4px solid #00d4ff;
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 5px;
            animation: fadeIn 0.3s ease-out;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .thinking-step .step-number {
            color: #00d4ff;
            font-weight: bold;
            margin-right: 10px;
        }
        
        .thinking-step .step-content {
            color: #ffffff;
        }
        
        .analysis-item {
            display: flex;
            justify-content: space-between;
            padding: 10px;
            margin-bottom: 8px;
            background: rgba(0, 255, 65, 0.05);
            border-radius: 5px;
            border: 1px solid rgba(0, 255, 65, 0.2);
        }
        
        .analysis-label {
            color: #00d4ff;
        }
        
        .analysis-value {
            color: #00ff41;
            font-weight: bold;
        }
        
        .threat-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin: 5px;
        }
        
        .threat-low { background: #00ff41; color: #0a0e27; }
        .threat-medium { background: #ffd700; color: #0a0e27; }
        .threat-high { background: #ff6600; color: #ffffff; }
        .threat-critical { background: #ff0066; color: #ffffff; animation: blink 1s infinite; }
        
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .timeline {
            position: relative;
            padding-left: 30px;
        }
        
        .timeline-item {
            position: relative;
            padding-bottom: 20px;
        }
        
        .timeline-item::before {
            content: '';
            position: absolute;
            left: -22px;
            top: 5px;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #00ff41;
            box-shadow: 0 0 10px #00ff41;
        }
        
        .timeline-item::after {
            content: '';
            position: absolute;
            left: -18px;
            top: 15px;
            width: 2px;
            height: calc(100% - 10px);
            background: rgba(0, 255, 65, 0.3);
        }
        
        .timeline-item:last-child::after {
            display: none;
        }
        
        .timeline-time {
            color: #00d4ff;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        
        .timeline-content {
            color: #ffffff;
        }
        
        .code-block {
            background: #000000;
            border: 1px solid #00ff41;
            border-radius: 5px;
            padding: 15px;
            overflow-x: auto;
            font-family: 'Consolas', monospace;
            color: #00ff41;
        }
        
        .waiting-message {
            text-align: center;
            padding: 50px;
            color: #00d4ff;
            font-size: 1.2em;
            animation: pulse 2s infinite;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: rgba(0, 212, 255, 0.1);
            border: 2px solid #00d4ff;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2.5em;
            color: #00ff41;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-label {
            color: #00d4ff;
            font-size: 0.9em;
        }
        
        .progress-bar {
            width: 100%;
            height: 25px;
            background: rgba(0, 0, 0, 0.5);
            border-radius: 12px;
            overflow: hidden;
            margin: 10px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00ff41, #00d4ff);
            border-radius: 12px;
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #0a0e27;
            font-weight: bold;
        }
        
        .json-viewer {
            background: #000000;
            border: 1px solid #00ff41;
            border-radius: 5px;
            padding: 15px;
            max-height: 300px;
            overflow-y: auto;
            font-size: 0.9em;
        }
        
        .json-key {
            color: #00d4ff;
        }
        
        .json-string {
            color: #ffd700;
        }
        
        .json-number {
            color: #ff6600;
        }
        
        .json-boolean {
            color: #ff0066;
        }
        
        ::-webkit-scrollbar {
            width: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.5);
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #00ff41;
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #00d4ff;
        }
        
        /* Tab Navigation */
        .tab-nav {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            background: rgba(0, 0, 0, 0.3);
            padding: 10px;
            border-radius: 8px;
            border: 1px solid rgba(0, 255, 65, 0.2);
        }
        
        .tab-btn {
            flex: 1;
            padding: 12px 20px;
            background: rgba(0, 212, 255, 0.1);
            border: 2px solid rgba(0, 212, 255, 0.3);
            border-radius: 6px;
            color: #00d4ff;
            cursor: pointer;
            font-size: 1em;
            font-weight: bold;
            transition: all 0.3s ease;
            font-family: 'Consolas', 'Monaco', monospace;
        }
        
        .tab-btn:hover {
            background: rgba(0, 212, 255, 0.2);
            border-color: #00d4ff;
            transform: translateY(-2px);
        }
        
        .tab-btn.active {
            background: rgba(0, 255, 65, 0.2);
            border-color: #00ff41;
            color: #00ff41;
            box-shadow: 0 0 15px rgba(0, 255, 65, 0.3);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
            animation: fadeIn 0.3s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🎯 AI HONEYPOT - LIVE DEMONSTRATION</h1>
            <p class="subtitle">
                <span class="status-indicator"></span>
                Real-Time Attack Analysis & Intelligence Processing
            </p>
        </header>
        
        <!-- Tab Navigation -->
        <div class="tab-nav">
            <button class="tab-btn active" onclick="switchTab('live-monitor')">📡 Live Monitor</button>
            <button class="tab-btn" onclick="switchTab('ai-intelligence')">🧠 AI Intelligence</button>
            <button class="tab-btn" onclick="switchTab('mitre-analysis')">🎯 MITRE Analysis</button>
            <button class="tab-btn" onclick="switchTab('threat-profile')">👤 Threat Profile</button>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Attacks</div>
                <div class="stat-value" id="total-attacks">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Current Attacker</div>
                <div class="stat-value" id="current-attacker" style="font-size: 1.2em;">WAITING</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Threat Level</div>
                <div class="stat-value" id="threat-level">LOW</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Skill Level</div>
                <div class="stat-value" id="skill-level">-</div>
            </div>
        </div>
        
        <!-- TAB 1: Live Monitor -->
        <div id="live-monitor" class="tab-content active">
            <div class="main-grid">
                <!-- Current Attack -->
                <div class="panel full-width">
                    <h2>🎯 INCOMING ATTACK</h2>
                    <div id="current-attack">
                        <div class="waiting-message">
                            Waiting for attack...
                        </div>
                    </div>
                </div>
                
                <!-- Attack Timeline -->
                <div class="panel full-width">
                    <h2>📊 ATTACK TIMELINE</h2>
                    <div class="timeline" id="attack-timeline">
                        <div class="waiting-message">
                            Attack history will appear here...
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- TAB 2: AI Intelligence -->
        <div id="ai-intelligence" class="tab-content">
            <div class="main-grid">
                <!-- LLM Thinking Process -->
                <div class="panel full-width">
                    <h2>🧠 LLM REASONING PROCESS</h2>
                    <div id="llm-thinking">
                        <div class="waiting-message">
                            LLM analysis will appear here...
                        </div>
                    </div>
                </div>
                
                <!-- AI Prediction Engine -->
                <div class="panel full-width">
                    <h2>🔮 NEXT ATTACK PREDICTION</h2>
                    <div id="prediction-display">
                        <div class="waiting-message">
                            Prediction data will appear after first attack...
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- TAB 3: MITRE Analysis -->
        <div id="mitre-analysis" class="tab-content">
            <div class="main-grid">
                <!-- MITRE ATT&CK Mapping -->
                <div class="panel full-width">
                    <h2>🎯 MITRE ATT&CK TECHNIQUES</h2>
                    <div id="mitre-display">
                        <div class="waiting-message">
                            MITRE mapping will appear after first attack...
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- TAB 4: Threat Profile -->
        <div id="threat-profile" class="tab-content">
            <div class="main-grid">
                <!-- Behavioral Profile -->
                <div class="panel">
                    <h2>👤 ATTACKER PROFILE</h2>
                    <div id="behavioral-profile">
                        <div class="waiting-message">
                            Behavioral analysis will appear here...
                        </div>
                    </div>
                </div>
                
                <!-- Threat Intelligence -->
                <div class="panel">
                    <h2>⚠️ THREAT INTELLIGENCE</h2>
                    <div id="threat-intel">
                        <div class="waiting-message">
                            Threat data will appear here...
                        </div>
                    </div>
                </div>
                
                <!-- Intelligence Analysis -->
                <div class="panel full-width">
                    <h2>🔍 INTELLIGENCE ANALYSIS</h2>
                    <div id="intelligence-analysis">
                        <div class="waiting-message">
                            Intelligence data will appear here...
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Tab switching function
        function switchTab(tabId) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all buttons
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Show selected tab
            const selectedTab = document.getElementById(tabId);
            if (selectedTab) {
                selectedTab.classList.add('active');
            }
            
            // Activate corresponding button
            event.target.classList.add('active');
        }
        
        const ws = new WebSocket('ws://localhost:8000/ws/demo');
        let attackCount = 0;
        let attackHistory = [];
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            
            if (data.type === 'attack') {
                handleAttack(data);
            } else if (data.type === 'llm_thinking') {
                updateLLMThinking(data.steps);
            } else if (data.type === 'intelligence') {
                updateIntelligence(data.analysis);
            } else if (data.type === 'behavioral') {
                updateBehavioral(data.profile);
            } else if (data.type === 'threat_intel') {
                updateThreatIntel(data.intel);
            }
        };
        
        function handleAttack(data) {
            attackCount++;
            attackHistory.unshift(data);
            if (attackHistory.length > 10) attackHistory.pop();
            
            // Update stats
            document.getElementById('total-attacks').textContent = attackCount;
            document.getElementById('current-attacker').textContent = data.attacker_id.substring(0, 8) + '...';
            document.getElementById('threat-level').textContent = data.threat_level || 'MEDIUM';
            document.getElementById('skill-level').textContent = data.skill_level || 'ANALYZING';
            
            // Update current attack display
            const attackHtml = `
                <div class="attack-display">
                    <div class="attack-label">⏰ Timestamp</div>
                    <div class="attack-value">${new Date(data.timestamp).toLocaleString()}</div>
                </div>
                <div class="attack-display">
                    <div class="attack-label">🎯 Attack Type</div>
                    <div class="attack-value">${data.attack_type}</div>
                </div>
                <div class="attack-display">
                    <div class="attack-label">🌐 IP Address</div>
                    <div class="attack-value">${data.ip}</div>
                </div>
                <div class="attack-display">
                    <div class="attack-label">📍 Endpoint</div>
                    <div class="attack-value">${data.endpoint}</div>
                </div>
                <div class="attack-display">
                    <div class="attack-label">💣 Payload</div>
                    <div class="code-block">${escapeHtml(data.payload)}</div>
                </div>
                <div class="attack-display">
                    <div class="attack-label">🔑 Attacker ID</div>
                    <div class="attack-value">${data.attacker_id}</div>
                </div>
            `;
            document.getElementById('current-attack').innerHTML = attackHtml;
            
            // Update timeline
            updateTimeline();
        }
        
        function updateLLMThinking(steps) {
            if (!steps || steps.length === 0) return;
            
            const html = steps.map((step, index) => `
                <div class="thinking-step">
                    <span class="step-number">Step ${index + 1}:</span>
                    <span class="step-content">${step}</span>
                </div>
            `).join('');
            
            document.getElementById('llm-thinking').innerHTML = html;
        }
        
        function updateIntelligence(analysis) {
            if (!analysis) return;
            
            const html = Object.entries(analysis).map(([key, value]) => `
                <div class="analysis-item">
                    <span class="analysis-label">${formatKey(key)}</span>
                    <span class="analysis-value">${value}</span>
                </div>
            `).join('');
            
            document.getElementById('intelligence-analysis').innerHTML = html;
        }
        
        function updateBehavioral(profile) {
            if (!profile) return;
            
            const html = `
                <div class="analysis-item">
                    <span class="analysis-label">Skill Level</span>
                    <span class="analysis-value">${profile.skill_level || 'Unknown'}</span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Tools Detected</span>
                    <span class="analysis-value">${(profile.tools || []).join(', ') || 'None'}</span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Attack Speed</span>
                    <span class="analysis-value">${profile.is_automated ? 'Automated' : 'Manual'}</span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Sophistication</span>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${profile.sophistication || 0}%">
                            ${profile.sophistication || 0}%
                        </div>
                    </div>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Total Attacks</span>
                    <span class="analysis-value">${profile.attack_count || 0}</span>
                </div>
            `;
            
            document.getElementById('behavioral-profile').innerHTML = html;
        }
        
        function updateThreatIntel(intel) {
            if (!intel) return;
            
            const threatClass = intel.threat_score > 80 ? 'threat-critical' :
                               intel.threat_score > 60 ? 'threat-high' :
                               intel.threat_score > 30 ? 'threat-medium' : 'threat-low';
            
            const html = `
                <div class="analysis-item">
                    <span class="analysis-label">Threat Score</span>
                    <span class="analysis-value">
                        <span class="threat-badge ${threatClass}">${intel.threat_score}/100</span>
                    </span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">IP Reputation</span>
                    <span class="analysis-value">${intel.reputation || 'Unknown'}</span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Country</span>
                    <span class="analysis-value">${intel.country || 'Unknown'}</span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Known Malicious</span>
                    <span class="analysis-value">${intel.is_malicious ? 'YES ⚠️' : 'NO ✓'}</span>
                </div>
                ${intel.sources ? `
                <div class="analysis-item">
                    <span class="analysis-label">Intel Sources</span>
                    <span class="analysis-value">${intel.sources.join(', ')}</span>
                </div>
                ` : ''}
            `;
            
            document.getElementById('threat-intel').innerHTML = html;
        }
        
        function updateTimeline() {
            const html = attackHistory.map(attack => `
                <div class="timeline-item">
                    <div class="timeline-time">${new Date(attack.timestamp).toLocaleTimeString()}</div>
                    <div class="timeline-content">
                        <strong>${attack.attack_type}</strong> from ${attack.ip}
                        <br>
                        <code>${attack.payload.substring(0, 50)}${attack.payload.length > 50 ? '...' : ''}</code>
                    </div>
                </div>
            `).join('');
            
            document.getElementById('attack-timeline').innerHTML = html || '<div class="waiting-message">No attacks yet...</div>';
        }
        
        function formatKey(key) {
            return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        ws.onopen = function() {
            console.log('Connected to demonstration dashboard');
        };
        
        ws.onerror = function(error) {
            console.error('WebSocket error:', error);
        };
    </script>
</body>
</html>
"""


def update_demo_attack(attack_data: Dict[str, Any]) -> None:
    """Update demonstration dashboard with new attack."""
    _demo_data["current_attack"] = attack_data


def update_demo_llm_thinking(steps: List[str]) -> None:
    """Update LLM thinking steps."""
    _demo_data["llm_thinking"] = steps


def update_demo_analysis(analysis: Dict[str, Any]) -> None:
    """Update intelligence analysis."""
    _demo_data["analysis_steps"] = analysis


def update_demo_threat_intel(intel: Dict[str, Any]) -> None:
    """Update threat intelligence data."""
    _demo_data["threat_intel"] = intel


def update_demo_behavioral(profile: Dict[str, Any]) -> None:
    """Update behavioral profile."""
    _demo_data["behavioral_profile"] = profile


def get_demo_data() -> Dict[str, Any]:
    """Get all demonstration data."""
    return _demo_data
