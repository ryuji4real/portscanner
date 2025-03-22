# 🔍 Port Scanner – A Fast & Flexible Network Scanning Tool

This repository contains a powerful Python-based **Port Scanner**, designed to detect open ports, identify services, and perform advanced scans on network targets. Whether you're a cybersecurity enthusiast, a pentester, or just exploring network tools, this scanner is built for speed and ease of use! 🌐🚀

### ✨ Features

✅ **Port Scanning**: Scan common ports or custom ranges (1-65535) with multi-threading  
✅ **Service Detection**: Retrieve service banners for open ports  
✅ **Common Ports**: Predefined list of 80+ frequently used ports with descriptions  
✅ **Advanced Scanning**: Optional Nmap integration for quick or detailed scans  
✅ **Results Logging**: Save scan results with timestamps in organized folders  
✅ **Customization**: Adjustable timeout, thread count, and silent mode  
✅ **Interface**: Interactive menu and full command-line support (CLI)  

---

## 🚀 Installation

### Prerequisites
This tool was developed and tested on **Windows** and **Linux**. It requires Python 3 and a few dependencies:

1️⃣ **Install Python 3**  
- Download Python from [python.org](https://www.python.org/downloads/).  
- Ensure `pip` is included (usually comes with Python).  

2️⃣ **Install Dependencies**  
Open a terminal and run:  
```bash
pip install colorama pyfiglet
```

3️⃣ **Install Nmap (Optional)**  
For advanced scanning:  
- Download Nmap from [nmap.org](https://nmap.org/download.html).  
- Add it to your system PATH or place it in the project folder.  
- Verify:  
  ```bash
  nmap -V
  ```

### Clone and Setup

1️⃣ **Clone the Repository**  
```bash
git clone https://github.com/ryuji4real/portscanner.git
```

2️⃣ **Navigate to the Project Folder**  
```bash
cd portscanner
```

3️⃣ **Verify Setup**  
Ensure Python and dependencies are working:  
```bash
python3 -c "import socket, colorama, pyfiglet"
```

---

## 🌐 Execution

### Option 1: Interactive Mode (Recommended)  
Launch the interactive menu:  
```bash
python3 scanner.py
```
- Follow the prompts to enter a target (IP/domain), choose ports, and configure options.  
- Example: Scan `scanme.nmap.org` → Select "no" for range → See open ports like 22 (SSH) or 80 (HTTP).

### Option 2: Command-Line Mode  
Run specific scans directly:  
- **Scan common ports**:  
  ```bash
  python3 scanner.py -t scanme.nmap.org -s
  ```  
  - Silent scan of common ports on `scanme.nmap.org`.  
- **Scan specific ports**:  
  ```bash
  python3 scanner.py -t 127.0.0.1 -p 80,443 -o
  ```  
  - Scan ports 80 and 443 on localhost, save results to file.  
- **Scan a range with Nmap**:  
  ```bash
  python3 scanner.py -t 192.168.1.1 -p 1-100 -n quick
  ```  
  - Quick Nmap scan of ports 1-100 on `192.168.1.1`.

### Notes
- Results are saved in `scan_results/YYYY-MM-DD/scan_X.txt` if the output option is enabled.  
- If Nmap isn’t installed, advanced scanning will be skipped with a warning.  

---

## 💡 Usage Examples

- **Interactive Mode**  
  ```bash
  python3 scanner.py
  ```  
  - Input: `scanme.nmap.org`, "no" for range, "no" for silent.  
  - Output: Lists open ports (e.g., `Port 80: OPEN (HTTP)`).  

- **CLI Mode**  
  ```bash
  python3 scanner.py -t scanme.nmap.org -p 22,80,443 -o
  ```  
  - Scans ports 22, 80, and 443 on `scanme.nmap.org`, saves results.  
  - Expected: `Port 22: OPEN (SSH)`, `Port 80: OPEN (HTTP)`, etc.  

- **With Nmap**:  
  ```bash
  python3 scanner.py -t 127.0.0.1 -p 1-1000 -n detailed -o
  ```  
  - Detailed Nmap scan of ports 1-1000 on localhost, saved to file.

---

💡 **Fast, flexible, and powerful – your go-to tool for network scanning!** 🚀
