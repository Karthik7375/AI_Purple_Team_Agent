# Building AI Agents for Cybersecurity: A Beginner's Tutorial

This tutorial will guide you through creating basic AI agents for red team and blue team operations, focusing on a practical implementation you can complete in two weeks.

## Part 1: Setting Up Your Environment

### Initial Setup
1. Create a virtual environment
```bash
python -m venv cyberagent-env
source cyberagent-env/bin/activate  # On Windows: cyberagent-env\Scripts\activate
```

2. Install the required packages
```bash
pip install numpy pandas scikit-learn flask requests matplotlib seaborn nltk scapy yara-python psutil
```

3. Create a project structure
```
cyberpurple/
├── agents/
│   ├── __init__.py
│   ├── red_agent.py
│   ├── blue_agent.py
│   └── utils.py
├── data/
│   ├── logs/
│   └── samples/
├── models/
│   ├── __init__.py
│   ├── decision_model.py
│   └── detection_model.py
├── interface/
│   ├── app.py
│   └── templates/
├── config.py
└── main.py
```

## Part 2: Creating a Basic Red Team Agent

The red team agent will simulate attacks and probe for vulnerabilities. Let's start with something simple but uncommon: timing-based reconnaissance and data exfiltration.

### File: agents/red_agent.py

```python
import time
import random
import requests
import scapy.all as scapy
import numpy as np
from sklearn.ensemble import RandomForestClassifier

class RedTeamAgent:
    def __init__(self, target_ip, config):
        self.target_ip = target_ip
        self.config = config
        self.learned_patterns = {}
        self.classifier = RandomForestClassifier()
        self.actions = [
            self.timing_based_recon,
            self.api_abuse_pattern,
            self.slow_exfiltration,
            self.living_off_cloud
        ]
        # Training data structure: [feature_vector, success_label]
        self.training_data = []
        self.training_labels = []
        
    def train_from_feedback(self, action_features, was_detected):
        """Learn from blue team detection results"""
        self.training_data.append(action_features)
        self.training_labels.append(0 if was_detected else 1)  # 1 if successful (not detected)
        
        # Only train after collecting enough samples
        if len(self.training_data) > 10:
            try:
                self.classifier.fit(self.training_data, self.training_labels)
                print("[+] Red Agent: Updated behavior model")
            except Exception as e:
                print(f"[-] Training error: {e}")
    
    def timing_based_recon(self):
        """Perform reconnaissance with variable timing to avoid detection"""
        print("[+] Red Agent: Performing timing-based reconnaissance")
        features = []
        
        # Create varying intervals between requests to avoid detection
        intervals = np.random.exponential(scale=2.0, size=5)
        
        for interval in intervals:
            # Sleep for random interval
            time.sleep(interval)
            
            # Simulate a network probe that looks like normal traffic
            try:
                response = requests.get(f"http://{self.target_ip}", 
                                       headers={"User-Agent": "Mozilla/5.0"},
                                       timeout=3)
                status = response.status_code
                features.append(interval)
                features.append(status)
            except:
                features.append(interval)
                features.append(0)
                
        return features
    
    def api_abuse_pattern(self):
        """Use legitimate API endpoints in unusual ways"""
        print("[+] Red Agent: Executing API abuse pattern")
        features = []
        
        # Legitimate but unusual API usage patterns
        endpoints = ["/api/users", "/api/status", "/api/config", "/api/health"]
        
        for endpoint in random.sample(endpoints, 3):
            try:
                # Use pagination parameters to extract data slowly
                params = {"limit": 1, "offset": random.randint(0, 100)}
                response = requests.get(f"http://{self.target_ip}{endpoint}", 
                                        params=params,
                                        timeout=2)
                features.append(1 if response.status_code == 200 else 0)
            except:
                features.append(0)
        
        return features
    
    def slow_exfiltration(self):
        """Simulate extremely slow data exfiltration"""
        print("[+] Red Agent: Attempting slow data exfiltration")
        features = []
        
        # Create a covert timing channel
        try:
            # Simulate exfiltrating data via timing between packets
            for i in range(3):
                # Convert some "secret data" to timing intervals
                secret_byte = random.randint(0, 255)
                delay = 0.1 + (secret_byte / 1000)  # Convert value to subtle timing difference
                time.sleep(delay)
                
                packet = scapy.IP(dst=self.target_ip)/scapy.TCP(dport=80)
                # Don't actually send in demo mode - just simulate
                # scapy.send(packet, verbose=0)
                
                features.append(delay)
                
        except Exception as e:
            print(f"[-] Exfiltration simulation error: {e}")
        
        return features
    
    def living_off_cloud(self):
        """Simulate exploiting cloud misconfiguration"""
        print("[+] Red Agent: Simulating cloud service exploitation")
        features = []
        
        # Target simulated serverless functions or S3-like storage
        cloud_targets = [
            f"http://{self.target_ip}/cloud/function/status",
            f"http://{self.target_ip}/cloud/storage/list",
            f"http://{self.target_ip}/cloud/iam/check"
        ]
        
        for target in cloud_targets:
            try:
                # Attempt to access with no credentials or default credentials
                response = requests.get(target, 
                                       headers={"X-Function-Key": "default-dev-key"},
                                       timeout=2)
                features.append(response.status_code)
            except:
                features.append(0)
        
        return features
    
    def choose_action(self):
        """Intelligently select action based on past success/failure"""
        if len(self.training_data) > 20 and random.random() > 0.3:
            # Create feature vectors for each potential action
            action_features = [action() for action in self.actions]
            
            # Predict success probability for each action
            predictions = self.classifier.predict_proba(action_features)
            success_probs = [p[1] for p in predictions]  # Probability of class 1 (success)
            
            # Choose action with highest predicted success rate
            best_action_idx = np.argmax(success_probs)
            return self.actions[best_action_idx], action_features[best_action_idx]
        else:
            # Initially, just randomly try actions to gather data
            action = random.choice(self.actions)
            features = action()
            return action, features
            
    def execute_attack(self):
        """Main method to execute attacks"""
        action, features = self.choose_action()
        return {"action": action.__name__, "features": features}
```

## Part 3: Creating a Basic Blue Team Agent

Now let's create a blue team agent focused on detection through log analysis and behavior monitoring.

### File: agents/blue_agent.py

```python
import numpy as np
import pandas as pd
import time
import re
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
import yara

class BlueTeamAgent:
    def __init__(self, config):
        self.config = config
        self.baseline_established = False
        # Anomaly detection model
        self.anomaly_detector = IsolationForest(contamination=0.1)
        # Store historical behaviors
        self.historical_behaviors = []
        # Detection counters
        self.alerts = []
        # Load basic YARA rules
        self.load_yara_rules()
        
    def load_yara_rules(self):
        """Load YARA rules for basic malware detection"""
        try:
            # Simple rule for demo purposes
            rule_string = """
            rule SuspiciousBehavior {
                strings:
                    $s1 = "default-dev-key" nocase
                    $s2 = "admin" nocase
                    $s3 = "password" nocase
                    $s4 = "cmd.exe" nocase
                    $s5 = "powershell" nocase
                condition:
                    any of them
            }
            """
            self.rules = yara.compile(source=rule_string)
            print("[+] Blue Agent: YARA rules loaded")
        except Exception as e:
            print(f"[-] YARA rule loading error: {e}")
            self.rules = None
            
    def process_logs(self, logs):
        """Analyze logs for suspicious patterns"""
        print("[+] Blue Agent: Processing logs")
        findings = []
        
        # Convert logs to dataframe for analysis
        try:
            if isinstance(logs, str):
                # Parse log string into structured format
                parsed_logs = self._parse_log_string(logs)
                df = pd.DataFrame(parsed_logs)
            else:
                df = pd.DataFrame(logs)
                
            # Extract features
            features = self._extract_features_from_logs(df)
            
            # Update historical data
            self.historical_behaviors.append(features)
            
            # Train model if we have enough data
            if len(self.historical_behaviors) >= 10 and not self.baseline_established:
                X = np.array(self.historical_behaviors)
                self.anomaly_detector.fit(X)
                self.baseline_established = True
                findings.append("Baseline behavior established")
            
            # Detect anomalies if baseline is established
            if self.baseline_established:
                X = np.array([features])
                prediction = self.anomaly_detector.predict(X)
                if prediction[0] == -1:  # Anomaly detected
                    findings.append("Anomalous behavior pattern detected")
                    # Add details of the anomaly
                    findings.append(f"Unusual timing patterns: intervals={features[0:3]}")
                    
        except Exception as e:
            findings.append(f"Log processing error: {e}")
            
        return findings
        
    def _parse_log_string(self, log_string):
        """Parse log string into structured format"""
        parsed_logs = []
        
        # Very simple parser for demonstration
        for line in log_string.strip().split('\n'):
            if not line:
                continue
                
            try:
                # Simple regex to extract timestamp, level, and message
                match = re.match(r'(\d+-\d+-\d+ \d+:\d+:\d+) \[(\w+)\] (.*)', line)
                if match:
                    timestamp, level, message = match.groups()
                    parsed_logs.append({
                        'timestamp': timestamp,
                        'level': level,
                        'message': message
                    })
                else:
                    parsed_logs.append({'message': line})
            except:
                parsed_logs.append({'message': line})
                
        return parsed_logs
        
    def _extract_features_from_logs(self, df):
        """Extract numerical features from log data"""
        features = []
        
        # Count log entries by level
        if 'level' in df.columns:
            level_counts = df['level'].value_counts()
            features.append(level_counts.get('ERROR', 0))
            features.append(level_counts.get('WARNING', 0))
            features.append(level_counts.get('INFO', 0))
            
        # Analyze time intervals if timestamp exists
        if 'timestamp' in df.columns and len(df) > 1:
            try:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df = df.sort_values('timestamp')
                time_diffs = df['timestamp'].diff().dropna()
                
                # Get statistics on time differences
                features.append(time_diffs.mean().total_seconds())
                features.append(time_diffs.std().total_seconds())
                features.append(time_diffs.max().total_seconds())
            except:
                # Default values if timestamp processing fails
                features.extend([0, 0, 0])
        else:
            features.extend([0, 0, 0])
            
        # Count common security-related keywords
        if 'message' in df.columns:
            text = ' '.join(df['message'].astype(str))
            features.append(text.count('error'))
            features.append(text.count('failed'))
            features.append(text.count('denied'))
            features.append(text.count('unauthorized'))
            features.append(text.count('timeout'))
        else:
            features.extend([0, 0, 0, 0, 0])
            
        return features
    
    def analyze_network_traffic(self, traffic_data):
        """Analyze network traffic for suspicious patterns"""
        print("[+] Blue Agent: Analyzing network traffic")
        findings = []
        
        # Look for suspicious timing patterns (potential covert channel)
        if 'intervals' in traffic_data:
            intervals = traffic_data['intervals']
            
            # Check for suspiciously consistent or patterned intervals
            if len(intervals) > 3:
                # Calculate differences between intervals
                diffs = np.diff(intervals)
                std_dev = np.std(diffs)
                
                # Too consistent timing may indicate automated tool
                if std_dev < 0.01:
                    findings.append("Suspiciously consistent timing between requests")
                
                # Check for encoding in timing
                clustering = DBSCAN(eps=0.05, min_samples=2).fit(np.array(intervals).reshape(-1, 1))
                if len(np.unique(clustering.labels_)) > 1:
                    findings.append("Possible timing-based covert channel detected")
        
        # Check for API abuse patterns
        if 'endpoints' in traffic_data:
            endpoints = traffic_data['endpoints']
            endpoint_counts = {}
            
            for endpoint in endpoints:
                endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
                
            # Check for excessive requests to the same endpoint
            for endpoint, count in endpoint_counts.items():
                if count > 5:
                    findings.append(f"Potential API abuse: {count} requests to {endpoint}")
                    
        return findings
    
    def scan_file(self, file_data, filename):
        """Scan a file for malicious content"""
        print(f"[+] Blue Agent: Scanning file {filename}")
        findings = []
        
        # Apply YARA rules if available
        if self.rules and isinstance(file_data, bytes):
            matches = self.rules.match(data=file_data)
            for match in matches:
                findings.append(f"YARA match: {match.rule}")
                
        # Look for suspicious patterns in the hex representation
        hex_data = file_data.hex() if isinstance(file_data, bytes) else str(file_data)
        suspicious_patterns = [
            "4d5a",       # MZ header (executable)
            "7f454c46",   # ELF header
            "504b0304",   # ZIP signature (could be concealing malware)
        ]
        
        for pattern in suspicious_patterns:
            if pattern in hex_data.lower():
                findings.append(f"Suspicious byte pattern detected: {pattern}")
                
        return findings
    
    def detect(self, red_agent_action):
        """Main detection method that analyzes red team actions"""
        action_name = red_agent_action.get('action', '')
        features = red_agent_action.get('features', [])
        
        print(f"[+] Blue Agent: Analyzing action {action_name}")
        
        # Initialize detection result
        detection = {
            'detected': False,
            'confidence': 0,
            'reasons': []
        }
        
        # Convert features to numpy array for analysis
        if features:
            # Normalize features for analysis
            features_array = np.array(features)
            
            # Apply different detection strategies based on the action type
            if 'timing_based_recon' in action_name:
                # Look for timing anomalies
                if self.baseline_established:
                    prediction = self.anomaly_detector.predict(features_array.reshape(1, -1))
                    if prediction[0] == -1:
                        detection['detected'] = True
                        detection['confidence'] = 0.7
                        detection['reasons'].append("Suspicious timing pattern detected")
                
            elif 'api_abuse' in action_name:
                # Check for API abuse patterns
                if sum(features) > 2:  # If multiple successful API calls
                    detection['detected'] = True
                    detection['confidence'] = 0.6
                    detection['reasons'].append("Multiple unusual API patterns detected")
                    
            elif 'slow_exfiltration' in action_name:
                # Analyze timing patterns in exfiltration
                if len(features) >= 3:
                    # Check for encoding patterns in timing
                    std_dev = np.std(features)
                    if 0.0001 < std_dev < 0.001:  # Very specific timing differences
                        detection['detected'] = True
                        detection['confidence'] = 0.8
                        detection['reasons'].append("Potential covert timing channel detected")
                        
            elif 'living_off_cloud' in action_name:
                # Check for cloud service exploitation
                if 200 in features:
                    detection['detected'] = True
                    detection['confidence'] = 0.75
                    detection['reasons'].append("Unauthorized cloud resource access detected")
        
        # Log the detection event
        self.alerts.append({
            'timestamp': time.time(),
            'action_type': action_name,
            'detected': detection['detected'],
            'confidence': detection['confidence'],
            'reasons': detection['reasons']
        })
        
        return detection
```

## Part 4: Creating a Simple Interaction Framework

Now let's create a framework to make these agents interact with each other and visualize the results.

### File: main.py

```python
import time
import random
import json
from agents.red_agent import RedTeamAgent
from agents.blue_agent import BlueTeamAgent
from flask import Flask, render_template, jsonify

# Configuration
config = {
    'target_ip': '127.0.0.1',
    'simulation_rounds': 20,
    'log_file': 'data/logs/simulation.log',
    'visualization_port': 5000
}

# Initialize agents
red_agent = RedTeamAgent(config['target_ip'], config)
blue_agent = BlueTeamAgent(config)

# Initialize Flask for visualization
app = Flask(__name__, template_folder='interface/templates')

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/data')
def get_data():
    return jsonify({
        'red_team_actions': red_actions,
        'blue_team_detections': blue_detections,
        'stats': {
            'detection_rate': calculate_detection_rate(),
            'false_positives': calculate_false_positives(),
        }
    })

def calculate_detection_rate():
    if not red_actions:
        return 0
    return sum(1 for d in blue_detections if d['detected']) / len(red_actions)

def calculate_false_positives():
    # In a real system, you'd have ground truth. Here we're simulating.
    return sum(1 for d in blue_detections if d['detected'] and random.random() < 0.1)

def run_simulation():
    """Run the main simulation loop"""
    global red_actions, blue_detections
    red_actions = []
    blue_detections = []
    
    print("[+] Starting Purple Team Simulation")
    
    for i in range(config['simulation_rounds']):
        print(f"\n--- Round {i+1}/{config['simulation_rounds']} ---")
        
        # Red team executes an action
        red_action = red_agent.execute_attack()
        red_actions.append(red_action)
        
        # Give the blue team a chance to detect
        blue_detection = blue_agent.detect(red_action)
        blue_detections.append(blue_detection)
        
        # Feed detection results back to red team for learning
        red_agent.train_from_feedback(red_action['features'], blue_detection['detected'])
        
        print(f"Action: {red_action['action']}")
        print(f"Detected: {blue_detection['detected']} ({blue_detection['confidence']:.2f} confidence)")
        if blue_detection['reasons']:
            print(f"Reasons: {', '.join(blue_detection['reasons'])}")
            
        time.sleep(1)  # Pause between rounds
    
    print("\n[+] Simulation complete")
    print(f"Detection rate: {calculate_detection_rate():.2f}")
    
    # Write results to file
    with open('data/logs/results.json', 'w') as f:
        json.dump({
            'red_actions': red_actions,
            'blue_detections': blue_detections,
            'stats': {
                'detection_rate': calculate_detection_rate(),
                'false_positives': calculate_false_positives(),
            }
        }, f, indent=2)

if __name__ == "__main__":
    # Run the simulation
    run_simulation()
    
    # Start the visualization server
    print(f"[+] Starting visualization server on port {config['visualization_port']}")
    app.run(host='0.0.0.0', port=config['visualization_port'])
```

### File: interface/templates/dashboard.html

```html
<!DOCTYPE html>
<html>
<head>
    <title>Purple Team Simulation Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { 
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        .container {
            display: flex;
            flex-wrap: wrap;
        }
        .chart-container {
            width: 48%;
            margin: 1%;
        }
        .stats-container {
            width: 98%;
            margin: 1%;
            padding: 15px;
            background-color: #f5f5f5;
            border-radius: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr.detected {
            background-color: #ffcccc;
        }
    </style>
</head>
<body>
    <h1>Purple Team AI Simulation Dashboard</h1>
    
    <div class="stats-container">
        <h2>Performance Metrics</h2>
        <div id="metrics"></div>
    </div>
    
    <div class="container">
        <div class="chart-container">
            <canvas id="detectionRate"></canvas>
        </div>
        <div class="chart-container">
            <canvas id="actionTypes"></canvas>
        </div>
    </div>
    
    <h2>Attack and Detection Log</h2>
    <table id="logTable">
        <thead>
            <tr>
                <th>Round</th>
                <th>Attack Type</th>
                <th>Detected</th>
                <th>Confidence</th>
                <th>Detection Reasons</th>
            </tr>
        </thead>
        <tbody id="logTableBody">
            <!-- Data will be inserted here -->
        </tbody>
    </table>
    
    <script>
        // Fetch data from the API
        async function fetchData() {
            const response = await fetch('/api/data');
            const data = await response.json();
            updateDashboard(data);
        }
        
        function updateDashboard(data) {
            // Update metrics
            const metricsDiv = document.getElementById('metrics');
            metricsDiv.innerHTML = `
                <p><strong>Detection Rate:</strong> ${(data.stats.detection_rate * 100).toFixed(2)}%</p>
                <p><strong>False Positives:</strong> ${data.stats.false_positives}</p>
                <p><strong>Total Attacks:</strong> ${data.red_team_actions.length}</p>
            `;
            
            // Update charts
            updateDetectionRateChart(data);
            updateActionTypesChart(data);
            
            // Update log table
            updateLogTable(data);
        }
        
        function updateDetectionRateChart(data) {
            const ctx = document.getElementById('detectionRate').getContext('2d');
            
            // Calculate detection success over time
            const labels = Array.from({length: data.red_team_actions.length}, (_, i) => `Round ${i+1}`);
            const detectionData = data.blue_team_detections.map(d => d.detected ? 1 : 0);
            
            // Calculate cumulative detection rate
            const cumulativeRate = [];
            let detected = 0;
            for (let i = 0; i < detectionData.length; i++) {
                detected += detectionData[i];
                cumulativeRate.push(detected / (i + 1));
            }
            
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Detection Success',
                            data: detectionData,
                            backgroundColor: 'rgba(255, 99, 132, 0.2)',
                            borderColor: 'rgba(255, 99, 132, 1)',
                            borderWidth: 1,
                            yAxisID: 'y1'
                        },
                        {
                            label: 'Cumulative Detection Rate',
                            data: cumulativeRate,
                            backgroundColor: 'rgba(54, 162, 235, 0.2)',
                            borderColor: 'rgba(54, 162, 235, 1)',
                            borderWidth: 2,
                            yAxisID: 'y'
                        }
                    ]
                },
                options: {
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 1,
                            title: {
                                display: true,
                                text: 'Cumulative Rate'
                            }
                        },
                        y1: {
                            beginAtZero: true,
                            max: 1,
                            position: 'right',
                            grid: {
                                drawOnChartArea: false
                            },
                            title: {
                                display: true,
                                text: 'Success (1 = Detected)'
                            }
                        }
                    }
                }
            });
        }
        
        function updateActionTypesChart(data) {
            const ctx = document.getElementById('actionTypes').getContext('2d');
            
            // Count attack types
            const attackTypes = {};
            data.red_team_actions.forEach(action => {
                const type = action.action;
                attackTypes[type] = (attackTypes[type] || 0) + 1;
            });
            
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: Object.keys(attackTypes),
                    datasets: [{
                        data: Object.values(attackTypes),
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.2)',
                            'rgba(54, 162, 235, 0.2)',
                            'rgba(255, 206, 86, 0.2)',
                            'rgba(75, 192, 192, 0.2)'
                        ],
                        borderColor: [
                            'rgba(255, 99, 132, 1)',
                            'rgba(54, 162, 235, 1)',
                            'rgba(255, 206, 86, 1)',
                            'rgba(75, 192, 192, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        title: {
                            display: true,
                            text: 'Attack Types Distribution'
                        }
                    }
                }
            });
        }
        
        function updateLogTable(data) {
            const tableBody = document.getElementById('logTableBody');
            tableBody.innerHTML = '';
            
            data.red_team_actions.forEach((action, index) => {
                const detection = data.blue_team_detections[index];
                const row = document.createElement('tr');
                if (detection.detected) {
                    row.classList.add('detected');
                }
                
                row.innerHTML = `
                    <td>${index + 1}</td>
                    <td>${action.action}</td>
                    <td>${detection.detected ? 'YES' : 'NO'}</td>
                    <td>${(detection.confidence * 100).toFixed(1)}%</td>
                    <td>${detection.reasons.join('<br>')}</td>
                `;
                
                tableBody.appendChild(row);
            });
        }
        
        // Initial load
        fetchData();
        
        // Refresh every 5 seconds
        setInterval(fetchData, 5000);
    </script>
</body>
</html>
```

## Part 5: Testing and Improving Your Agents

To make your agents smarter and more effective:

1. **Expand the Red Team's techniques**:
   - Add more sophisticated evasion techniques
   - Implement technique chaining (combine multiple approaches)
   - Add learning from past attempts

2. **Enhance the Blue Team's detection**:
   - Add more advanced log correlation
   - Implement anomaly detection with more sophisticated models
   - Create custom detection rules for the uncommon techniques

3. **Testing Methodology**:
   - Run your simulation with different configurations
   - Analyze which techniques are most successful
   - Tune the detection thresholds based on results

## Part 6: Going Further

Some ideas to extend your project if you have time:

1. **Reinforcement Learning**: Use RL algorithms to have your red an