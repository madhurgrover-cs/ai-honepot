"""
Real-Time Dashboard for AI Honeypot
Web-based dashboard with live attack feed, statistics, and visualization.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from typing import List, Dict, Any
from datetime import datetime, timedelta
import json
import asyncio
from collections import defaultdict, Counter


# =========================
# DASHBOARD DATA AGGREGATOR
# =========================
class DashboardDataAggregator:
    """Aggregates data for dashboard display."""
    
    def __init__(self):
        self.recent_attacks: List[Dict[str, Any]] = []
        self.attack_stats = defaultdict(int)
        self.attacker_stats = defaultdict(int)
        self.endpoint_stats = defaultdict(int)
        self.skill_level_stats = defaultdict(int)
        self.country_stats = defaultdict(int)
        
        # WebSocket connections
        self.active_connections: List[WebSocket] = []
    
    def add_attack(self, attack_data: Dict[str, Any]) -> None:
        """Add new attack to dashboard."""
        # Add to recent attacks (keep last 100)
        self.recent_attacks.insert(0, attack_data)
        if len(self.recent_attacks) > 100:
            self.recent_attacks.pop()
        
        # Update statistics
        attack_type = attack_data.get("attack_type", "UNKNOWN")
        self.attack_stats[attack_type] += 1
        
        attacker_id = attack_data.get("attacker_id", "unknown")
        self.attacker_stats[attacker_id] += 1
        
        endpoint = attack_data.get("endpoint", "unknown")
        self.endpoint_stats[endpoint] += 1
        
        skill_level = attack_data.get("skill_level", "unknown")
        self.skill_level_stats[skill_level] += 1
        
        country = attack_data.get("country", "unknown")
        self.country_stats[country] += 1
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get all dashboard data."""
        return {
            "recent_attacks": self.recent_attacks[:20],  # Last 20 attacks
            "total_attacks": sum(self.attack_stats.values()),
            "unique_attackers": len(self.attacker_stats),
            "attack_type_distribution": dict(self.attack_stats),
            "endpoint_distribution": dict(self.endpoint_stats),
            "skill_level_distribution": dict(self.skill_level_stats),
            "country_distribution": dict(self.country_stats),
            "top_attackers": self._get_top_attackers(),
            "attack_timeline": self._get_attack_timeline(),
        }
    
    def _get_top_attackers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top attackers by attack count."""
        return [
            {"attacker_id": attacker_id, "count": count}
            for attacker_id, count in sorted(
                self.attacker_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:limit]
        ]
    
    def _get_attack_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get attack timeline for last N hours."""
        # Group attacks by hour
        timeline = defaultdict(int)
        cutoff = datetime.now() - timedelta(hours=hours)
        
        for attack in self.recent_attacks:
            timestamp_str = attack.get("timestamp")
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str)
                    if timestamp > cutoff:
                        hour_key = timestamp.strftime("%Y-%m-%d %H:00")
                        timeline[hour_key] += 1
                except:
                    pass
        
        return [
            {"time": time, "count": count}
            for time, count in sorted(timeline.items())
        ]
    
    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast message to all connected WebSocket clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                disconnected.append(connection)
        
        # Remove disconnected clients
        for connection in disconnected:
            self.active_connections.remove(connection)


# =========================
# DASHBOARD HTML
# =========================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Honeypot Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-value {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-label {
            font-size: 1.1em;
            opacity: 0.8;
        }
        
        .main-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
        }
        
        .panel {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .panel h2 {
            margin-bottom: 20px;
            font-size: 1.5em;
        }
        
        .attack-feed {
            max-height: 500px;
            overflow-y: auto;
        }
        
        .attack-item {
            background: rgba(255, 255, 255, 0.05);
            border-left: 4px solid #ff6b6b;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            animation: slideIn 0.3s ease-out;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        .attack-item.sql-injection { border-left-color: #ff6b6b; }
        .attack-item.xss { border-left-color: #feca57; }
        .attack-item.cmd-injection { border-left-color: #ff9ff3; }
        .attack-item.normal { border-left-color: #48dbfb; }
        
        .attack-time {
            font-size: 0.9em;
            opacity: 0.7;
        }
        
        .attack-type {
            display: inline-block;
            background: rgba(255, 255, 255, 0.2);
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            margin: 5px 5px 5px 0;
        }
        
        .chart-container {
            margin-top: 20px;
        }
        
        .bar-chart {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        
        .bar-item {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .bar-label {
            min-width: 120px;
            font-size: 0.9em;
        }
        
        .bar-fill {
            flex: 1;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            overflow: hidden;
        }
        
        .bar-progress {
            height: 30px;
            background: linear-gradient(90deg, #667eea, #764ba2);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 10px;
            transition: width 0.5s ease;
        }
        
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #2ecc71;
            animation: pulse 2s infinite;
            margin-right: 8px;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.3);
            border-radius: 10px;
        }
        
        @media (max-width: 768px) {
            .main-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🍯 AI Honeypot Dashboard</h1>
            <p class="subtitle">
                <span class="status-indicator"></span>
                Real-Time Attack Monitoring
            </p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Attacks</div>
                <div class="stat-value" id="total-attacks">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique Attackers</div>
                <div class="stat-value" id="unique-attackers">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Active Now</div>
                <div class="stat-value" id="active-now">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Threat Level</div>
                <div class="stat-value" id="threat-level">LOW</div>
            </div>
        </div>
        
        <div class="main-grid">
            <div class="panel">
                <h2>📡 Live Attack Feed</h2>
                <div class="attack-feed" id="attack-feed">
                    <p style="opacity: 0.5; text-align: center; padding: 50px 0;">
                        Waiting for attacks...
                    </p>
                </div>
            </div>
            
            <div class="panel">
                <h2>📊 Attack Distribution</h2>
                <div class="chart-container">
                    <div class="bar-chart" id="attack-chart"></div>
                </div>
                
                <h2 style="margin-top: 30px;">🎯 Skill Levels</h2>
                <div class="chart-container">
                    <div class="bar-chart" id="skill-chart"></div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const ws = new WebSocket('ws://localhost:8000/ws/dashboard');
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            
            if (data.type === 'attack') {
                addAttackToFeed(data.attack);
            } else if (data.type === 'stats') {
                updateStats(data.stats);
            }
        };
        
        ws.onopen = function() {
            console.log('Connected to dashboard');
        };
        
        ws.onerror = function(error) {
            console.error('WebSocket error:', error);
        };
        
        function addAttackToFeed(attack) {
            const feed = document.getElementById('attack-feed');
            
            // Remove "waiting" message if present
            if (feed.querySelector('p')) {
                feed.innerHTML = '';
            }
            
            const attackClass = attack.attack_type.toLowerCase().replace(/ /g, '-');
            const item = document.createElement('div');
            item.className = `attack-item ${attackClass}`;
            item.innerHTML = `
                <div class="attack-time">${new Date(attack.timestamp).toLocaleTimeString()}</div>
                <div>
                    <span class="attack-type">${attack.attack_type}</span>
                    <span class="attack-type">${attack.skill_level || 'Unknown'}</span>
                    ${attack.country ? `<span class="attack-type">${attack.country}</span>` : ''}
                </div>
                <div style="margin-top: 8px; font-size: 0.9em; opacity: 0.8;">
                    ${attack.endpoint} - ${attack.ip}
                </div>
                <div style="margin-top: 5px; font-size: 0.85em; opacity: 0.6; font-family: monospace;">
                    ${attack.payload.substring(0, 80)}${attack.payload.length > 80 ? '...' : ''}
                </div>
            `;
            
            feed.insertBefore(item, feed.firstChild);
            
            // Keep only last 20 attacks
            while (feed.children.length > 20) {
                feed.removeChild(feed.lastChild);
            }
        }
        
        function updateStats(stats) {
            document.getElementById('total-attacks').textContent = stats.total_attacks || 0;
            document.getElementById('unique-attackers').textContent = stats.unique_attackers || 0;
            document.getElementById('active-now').textContent = stats.active_now || 0;
            
            // Update threat level
            const threatLevel = calculateThreatLevel(stats.total_attacks);
            document.getElementById('threat-level').textContent = threatLevel;
            
            // Update attack distribution chart
            updateChart('attack-chart', stats.attack_type_distribution || {});
            
            // Update skill level chart
            updateChart('skill-chart', stats.skill_level_distribution || {});
        }
        
        function updateChart(chartId, data) {
            const chart = document.getElementById(chartId);
            chart.innerHTML = '';
            
            const maxValue = Math.max(...Object.values(data), 1);
            
            for (const [label, value] of Object.entries(data)) {
                const percentage = (value / maxValue) * 100;
                
                const barItem = document.createElement('div');
                barItem.className = 'bar-item';
                barItem.innerHTML = `
                    <div class="bar-label">${label}</div>
                    <div class="bar-fill">
                        <div class="bar-progress" style="width: ${percentage}%">
                            ${value}
                        </div>
                    </div>
                `;
                chart.appendChild(barItem);
            }
        }
        
        function calculateThreatLevel(totalAttacks) {
            if (totalAttacks < 10) return 'LOW';
            if (totalAttacks < 50) return 'MEDIUM';
            if (totalAttacks < 100) return 'HIGH';
            return 'CRITICAL';
        }
        
        // Request initial stats
        setTimeout(() => {
            ws.send(JSON.stringify({type: 'get_stats'}));
        }, 1000);
        
        // Refresh stats every 5 seconds
        setInterval(() => {
            ws.send(JSON.stringify({type: 'get_stats'}));
        }, 5000);
    </script>
</body>
</html>
"""


# =========================
# GLOBAL INSTANCE
# =========================
_dashboard = DashboardDataAggregator()


def get_dashboard_html() -> str:
    """Get dashboard HTML."""
    return DASHBOARD_HTML


def add_attack_to_dashboard(attack_data: Dict[str, Any]) -> None:
    """Add attack to dashboard (convenience function)."""
    _dashboard.add_attack(attack_data)


def get_dashboard_stats() -> Dict[str, Any]:
    """Get dashboard statistics (convenience function)."""
    return _dashboard.get_dashboard_data()


async def broadcast_attack(attack_data: Dict[str, Any]) -> None:
    """Broadcast attack to dashboard (convenience function)."""
    await _dashboard.broadcast({
        "type": "attack",
        "attack": attack_data
    })


async def broadcast_stats() -> None:
    """Broadcast stats to dashboard (convenience function)."""
    stats = _dashboard.get_dashboard_data()
    stats["active_now"] = len(_dashboard.active_connections)
    await _dashboard.broadcast({
        "type": "stats",
        "stats": stats
    })


def get_active_connections() -> List[WebSocket]:
    """Get active WebSocket connections."""
    return _dashboard.active_connections
