# AI Bug Hunter Installation Guide

This document provides a technical walkthrough for installing and the environment setup for the **Raven AI security scanner**.

---

## 💻 1. System Requirements

*   **Operating System**: Linux (Ubuntu/Debian recommended) or macOS.
*   **Python Version**: Python 3.11 or higher (required for latest type-hinting and performance features).
*   **System Libraries**: Ensure `libssl-dev` and `libffi-dev` are installed (mostly for SSL and FAISS support).

---

## 📦 2. Virtual Environment Setup (Recommended)

To avoid conflicts with other system packages, always install Raven AI in a dedicated virtual environment.

### Using Python venv
1. **Create the environment**:
   ```bash
   python3 -m venv venv
   ```
2. **Activate the environment**:
   - On Linux/macOS:
     ```bash
     source venv/bin/activate
     ```
   - On Windows:
     ```bash
     .\venv\Scripts\activate
     ```

---

## 🛠️ 3. Installing Dependencies

Once your virtual environment is active, install the necessary Python packages:

```bash
# Upgrade pip to the latest version first
pip install --upgrade pip

# Install all core and scanning dependencies
pip install -r requirements.txt
```

---

## 🛡️ 4. Optional Toolchain Setup

Raven AI includes wrappers for industry-standard tools to expand its scanning capabilities. To enable these, follow the steps below:

### Nuclei (Template-based Scanning)
1. **Download**: Install from [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei).
2. **Setup**: Ensure the `nuclei` binary is in your system's PATH.
3. **Templates**: Run `nuclei -update-templates`.

### FFUF (Fast Web Fuzzer)
1. **Download**: Install from [ffuf/ffuf](https://github.com/ffuf/ffuf).
2. **Setup**: Ensure the `ffuf` binary is in your system's PATH.

### SQLMap (SQL Injection Tool)
1. **Download**: Install from [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap).
2. **Setup**: If running as a standalone script, update the `sqlmap.py` binary path in `configs/settings.yaml`.

### DalFox (XSS Scanner)
1. **Download**: Install from [hahwul/dalfox](https://github.com/hahwul/dalfox).
2. **Setup**: Ensure the `dalfox` binary is in your system's PATH.

---

## ✅ 5. Verifying the Installation

To verify that everything is correctly installed and ready for use, run the version check:

```bash
python3 main.py --help
```

If the help menu appears without errors, the installation is complete and you are ready to start scanning.
