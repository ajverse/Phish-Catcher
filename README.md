# Phish_Catcher
# Phishing & IP Checker (Kivy App)

A Python-based application that helps users check if an IP or URL is **malicious, blacklisted, or a phishing link** using **Kivy for UI and backend**. The project logs past searches in a CSV file and provides a direct link for Indian users to report cyber crimes.

---

## Features

✅ IP Reputation Check
✅ URL Phishing Scanner
✅ Logs past searches in a CSV file
✅ Kivy UI for later Android compatibility use cases
✅ Enhanced security measures with sandboxed environment
✅ Direct link to report cybercrimes (for Indian citizens)

---

# Project Structure

Phishing_Checker_Project/
│── app/
│   ├── main.py            # Kivy-based application backend and UI
│   ├── checkers.py        # Helper functions for checking URLs/IPs
│   ├── buildozer.spec     # Buildozer configuration for APK conversion
│── logs/
│   ├── checked_urls.csv   # Stores checked URLs/IPs
│── README.md              # Project documentation
│── requirements.txt       # Required dependencies

---

# Installation & Setup

## Prerequisites

- Python 3.x
- `pip` installed
- Python libraries

# Implementation Approaches (API optional and not used for this application)

### ✅ Features:
- URL & IP reputation checks.
- blacklisted IP detection.
- Exception handling if APIs fail or rate limits exceed.
- Stores results in a CSV file for future reference.
- Direct cybercrime reporting link for Indian users.
- Secured against external API failures.(in codes of Previous versions with API calls)

### ✅ Features:
- Uses `vt` Python client instead of direct API calls.
- No manual API key handling is needed in the code.
- Automatically fetches IP/URL analysis from VirusTotal.
- Stores results in a CSV file.
- Includes a direct cybercrime reporting link.
- Enhanced security for Android execution.

# CSV Logging Feature

Each checked URL or IP is stored in `logs/checked_urls.csv` with details:
```
Type, Input, Checked Date, Result
URL, www.example.com, 2025-01-30, Safe
IP, 192.168.1.1, 2025-01-30, Blacklisted
```

---

# Cybercrime Reporting (India)

For Indian citizens, users can **report malicious URLs or IPs** directly through:
**[Cybercrime Report Portal](https://cybercrime.gov.in/Webform/Crime_AuthoLogin.aspx)**

The Kivy UI includes a clickable button to access this portal.

---

# License

This project is open-source and licensed under the MIT License.

---

# Contact

For any issues, feel free to raise an issue on GitHub or reach out at:
📧 **ashutoshjena2001@yahoo.com**

