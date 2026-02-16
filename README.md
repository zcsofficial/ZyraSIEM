# Zyra SIEM

**Zyra SIEM** is a comprehensive Security Information and Event Management system designed for Windows environments. It provides real-time monitoring, threat detection, and centralized security event management through an agent-based architecture.

![Zyra SIEM](https://img.shields.io/badge/Version-1.0.0-purple)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## ✨ Features

### Core Capabilities

- **Real-time Monitoring**: Continuous collection of system metrics, processes, and network activity
- **Threat Detection**: Automated malware scanning using VirusTotal API integration
- **Anomaly Detection**: Intelligent detection of suspicious activities including:
  - High CPU usage (>90%)
  - Multiple failed login attempts
  - Unusual login times
  - Suspicious processes
  - File deletion events
  - Registry changes
- **Network Analysis**: DNS query monitoring and network traffic analysis with IP geolocation
- **Windows Event Log Integration**: Comprehensive collection of System and Security event logs
- **Offline Support**: Local SQLite storage when MongoDB connection is unavailable
- **Web Dashboard**: Modern, responsive web interface for monitoring and analysis
- **Real-time Updates**: WebSocket-based live dashboard updates

### Security Features

- Malware detection via VirusTotal
- Failed login attempt tracking
- Privilege escalation monitoring
- Registry change detection
- Network traffic analysis
- Process behavior monitoring

## 🏗️ Architecture

Zyra SIEM follows a three-tier architecture:

```
┌─────────────────┐
│  Web Dashboard  │  (Port 5001)
│     (app.py)    │
└────────┬────────┘
         │
┌────────▼────────┐
│   API Server    │  (Port 5000)
│   (server.py)   │
└────────┬────────┘
         │
┌────────▼────────┐
│   MongoDB       │
│   (Atlas)       │
└─────────────────┘
         ▲
         │
┌────────┴────────┐
│  Agent (Windows)│
│   (agent.py)    │
└─────────────────┘
```

### Components

1. **Agent (`agent.py`)**: Windows-based monitoring agent that collects system data
2. **API Server (`server.py`)**: FastAPI backend providing REST API and WebSocket endpoints
3. **Web Application (`app.py`)**: Frontend server serving the dashboard interface
4. **MongoDB**: Centralized database for logs, alerts, and device information

## 📦 Prerequisites

### System Requirements

- **OS**: Windows 10/11 or Windows Server
- **Python**: 3.8 or higher
- **Administrator Privileges**: Required for agent execution
- **Network**: Internet connection for MongoDB Atlas and API services

### External Services

- MongoDB Atlas account (or local MongoDB instance)
- VirusTotal API key (optional, for malware scanning)
- ipinfo.io token (for IP geolocation)

## 🚀 Installation

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd ZyraSIEM
```

### Step 2: Install Python Dependencies

```bash
pip install pymongo requests psutil uuid dnspython scapy ipinfo pywin32 pillow virustotal-python wget tenacity fastapi uvicorn aiohttp jinja2
```

Or install from requirements (if available):

```bash
pip install -r requirements.txt
```

### Step 3: Install Npcap

Npcap is required for network packet capture. Run the setup script:

```bash
python setup.py
```

Alternatively, download and install manually from [https://npcap.com](https://npcap.com)

**Note**: The setup script requires administrator privileges.

### Step 4: Configure MongoDB

1. Create a MongoDB Atlas cluster or use a local MongoDB instance
2. Update the MongoDB connection string in `server.py` and `agent.py`:

```python
DB_PASSWORD = "your_password"
ENCODED_PASSWORD = quote(DB_PASSWORD)
MONGO_URI = f"mongodb+srv://zyraadmin:{ENCODED_PASSWORD}@your-cluster.mongodb.net/?retryWrites=true&w=majority&appName=ZyraSiemCluster"
```

### Step 5: Configure API Keys (Optional)

#### VirusTotal API Key

Update the API endpoint in `agent.py`:

```python
VT_API_KEY_URL = f"{API_SERVER_URL}/get_vt_api_key"
```

Or set directly:

```python
VT_API_KEY = "your_virustotal_api_key"
```

#### ipinfo.io Token

Update in `agent.py`:

```python
IPINFO_TOKEN = "your_ipinfo_token"
```

## ⚙️ Configuration

### Agent Configuration

The agent automatically generates a unique `AGENT_ID` based on the Windows Machine GUID. This ensures persistent identification across restarts.

### Server Configuration

- **API Server Port**: Default `5000` (configurable in `server.py`)
- **Web Server Port**: Default `5001` (configurable in `app.py`)

### Database Collections

The system uses three main MongoDB collections:

- `device_info`: Agent device information
- `logs`: System logs and metrics
- `alerts`: Security alerts and anomalies

## 🎯 Usage

### Starting the System

#### 1. Start the API Server

```bash
python server.py
```

The API server will start on `http://localhost:5000`

#### 2. Start the Web Application

```bash
python app.py
```

The web dashboard will be available at `http://localhost:5001`

#### 3. Run the Agent

**Important**: Run as Administrator

```bash
python agent.py
```

The agent will:
- Elevate to administrator privileges automatically
- Connect to MongoDB
- Start monitoring threads
- Begin collecting and sending data

### Accessing the Dashboard

1. Open your web browser
2. Navigate to `http://localhost:5001`
3. View real-time dashboard with:
   - Total agents count
   - Total logs
   - Total alerts
   - Recent alerts table
   - Real-time activity chart

### Dashboard Pages

- **Dashboard** (`/`): Overview with key metrics and recent alerts
- **Alerts** (`/alerts`): All security alerts with filtering options
- **Logs** (`/logs`): System logs and events
- **Agents** (`/agents`): List of all registered agents
- **Agent Details** (`/agent/{agent_id}`): Detailed view of a specific agent
- **Malware Analysis** (`/malware`): Malware detection results

## 📡 API Documentation

### REST Endpoints

#### Dashboard Data
```
GET /api/v1/dashboard
```
Returns overview statistics including total agents, logs, alerts, and recent alerts.

#### Logs
```
GET /api/v1/logs?limit=100&offset=0&search=&sort_by=timestamp&sort_order=desc&severity=&source=
```
Query parameters:
- `limit`: Number of results (1-1000)
- `offset`: Pagination offset
- `search`: Text search query
- `sort_by`: Field to sort by
- `sort_order`: `asc` or `desc`
- `severity`: Filter by severity level
- `source`: Filter by agent ID

#### Alerts
```
GET /api/v1/alerts?limit=100&offset=0&search=&sort_by=timestamp&sort_order=desc&severity=
```
Similar parameters to logs endpoint.

#### Agents
```
GET /api/v1/agents?limit=100&offset=0&sort_by=last_updated&sort_order=desc
```

#### Agent Details
```
GET /api/v1/agent/{agent_id}
```
Returns agent information, logs, and alerts for a specific agent.

#### Malware
```
GET /api/v1/malware?limit=100&offset=0&sort_by=timestamp&sort_order=desc
```

### WebSocket Endpoint

#### Real-time Dashboard Updates
```
WS /ws/dashboard
```
Sends dashboard data every 2 seconds.

## 📁 Project Structure

```
ZyraSIEM/
├── agent.py                 # Windows monitoring agent
├── server.py                # FastAPI API server
├── app.py                   # Web frontend server
├── setup.py                 # Npcap installation script
├── README.md                # Project documentation
├── readme.txt               # Quick installation notes
├── templates/               # HTML templates
│   ├── dashboard.html      # Main dashboard page
│   ├── alerts.html         # Alerts page
│   ├── logs.html           # Logs page
│   ├── agents.html         # Agents list page
│   ├── agent.html          # Agent details page
│   └── malware.html         # Malware analysis page
├── local_storage.db         # SQLite fallback database
├── agent.log               # Agent execution logs
├── server.log              # API server logs
└── webui.log               # Web application logs
```

## 🛠️ Technology Stack

### Backend
- **FastAPI**: Modern, fast web framework for building APIs
- **Uvicorn**: ASGI server
- **MongoDB**: NoSQL database for data storage
- **SQLite**: Local fallback storage
- **Pymongo**: MongoDB Python driver

### Monitoring & Analysis
- **psutil**: System and process utilities
- **scapy**: Network packet manipulation
- **win32evtlog**: Windows Event Log access
- **VirusTotal API**: Malware scanning
- **ipinfo.io**: IP geolocation

### Frontend
- **Tailwind CSS**: Utility-first CSS framework
- **ECharts**: Data visualization library
- **Jinja2**: Template engine
- **WebSocket**: Real-time communication

### Python Libraries
- `requests`: HTTP library
- `aiohttp`: Async HTTP client/server
- `PIL/Pillow`: Image processing
- `tenacity`: Retry library

## 🔒 Security Considerations

### Important Security Notes

1. **Credentials**: MongoDB passwords and API keys are currently hardcoded. **It is strongly recommended** to:
   - Use environment variables
   - Implement a configuration file with proper access controls
   - Use secrets management solutions

2. **Administrator Privileges**: The agent requires admin privileges to:
   - Access Windows Event Logs
   - Monitor network traffic
   - Capture system metrics
   - Monitor registry changes

3. **Network Security**: Ensure MongoDB Atlas has proper IP whitelisting and authentication enabled.

4. **API Security**: Consider implementing:
   - Authentication/Authorization
   - Rate limiting
   - HTTPS/TLS encryption
   - API key management

### Best Practices

- Run agents only on trusted systems
- Regularly update dependencies
- Monitor agent logs for suspicious activity
- Implement proper backup strategies for MongoDB
- Use VPN or secure networks for agent-server communication

## 🐛 Troubleshooting

### Common Issues

#### Agent Won't Start
- **Issue**: Permission denied errors
- **Solution**: Run as Administrator

#### MongoDB Connection Failed
- **Issue**: Cannot connect to MongoDB Atlas
- **Solutions**:
  - Verify MongoDB URI and credentials
  - Check IP whitelist in MongoDB Atlas
  - Verify internet connectivity
  - Check firewall settings

#### Network Capture Not Working
- **Issue**: Scapy errors or no network data
- **Solutions**:
  - Ensure Npcap is installed
  - Run agent as Administrator
  - Check network adapter permissions

#### VirusTotal API Errors
- **Issue**: Malware scanning fails
- **Solutions**:
  - Verify API key is valid
  - Check API rate limits
  - Ensure internet connectivity

### Log Files

Check the following log files for detailed error information:

- `agent.log`: Agent execution logs
- `server.log`: API server logs
- `webui.log`: Web application logs
- `setup.log`: Setup script logs

### Offline Mode

The agent automatically falls back to local SQLite storage when MongoDB is unavailable. Data will sync when connectivity is restored.

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup

1. Set up a virtual environment:
```bash
python -m venv venv
venv\Scripts\activate  # Windows
```

2. Install development dependencies:
```bash
pip install -r requirements.txt
```

3. Configure local MongoDB or use MongoDB Atlas free tier

## 📝 License

[Specify your license here]

## 📧 Contact & Support

For issues, questions, or contributions, please [create an issue](link-to-issues) or contact the maintainers.

---

**Note**: This is a security monitoring tool. Use responsibly and in compliance with applicable laws and regulations. Ensure you have proper authorization before monitoring systems.
