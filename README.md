# Slayer Log Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.7+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/platform-Android-brightgreen.svg" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-orange.svg" alt="License">
</p>

<p align="center"><strong>Crafted by Slayer</strong></p>


A powerful security tool for Android security researchers and penetration testers that captures and analyzes logcat output to identify sensitive data leaks in Android applications.

The big idea is run this test or use applications normally and it'll analysis y the logs side by side...


## 🎯 Features

- **🔍 Comprehensive Pattern Detection**: Scans for 30+ types of sensitive data patterns
- **🧠 Entropy Analysis**: Detects high-entropy tokens that regex patterns might miss (API keys, secrets, tokens)
- **🎯 PID-Based Capture**: Captures ALL logs from target process (OkHttp, WebView, System.out, etc.)
- **📊 Multiple Report Formats**: Generates both interactive HTML and plain text reports
- **🎨 Beautiful UI**: Color-coded console output and searchable HTML reports
- **⚡ Real-time Capture**: Live monitoring with manual stop control
- **🔧 Customizable**: Add custom keywords and regex patterns

## 🚨 Detection Capabilities

### Authentication & Authorization
- JWT tokens, Bearer tokens, OAuth tokens
- API keys and secrets
- Session cookies
- Authorization headers
- Firebase/FCM tokens

### Personal Identifiable Information (PII)
- Email addresses
- Mobile phone numbers (with Indian +91 prefix support)
- Names, addresses, dates of birth
- Aadhaar numbers (India)
- PAN card numbers (India)
- Device IDs, Customer IDs

### Financial Data
- UPI URIs and VPAs
- Credit/debit card numbers
- CVV codes
- Bank account numbers
- Transaction IDs
- Payment gateway keys (Razorpay, Paytm, PhonePe, etc.)

### Cloud & Technical Data
- AWS credentials (access keys, secret keys)
- Private keys (RSA, SSH, PEM)
- Database credentials (MongoDB, PostgreSQL, MySQL)
- Internal URLs and IPs
- Version strings and debug flags

## 📋 Requirements

- **Python 3.7+**
- **Android Debug Bridge (ADB)**
- **USB debugging enabled** on target device
- **Rooted device** (recommended for complete log access)

## 🚀 Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/slayer-log-scanner.git
cd slayer-log-scanner
```

### 2. Ensure ADB is installed
```bash
adb version
```

If not installed:
- **macOS**: `brew install android-platform-tools`
- **Linux**: `sudo apt-get install adb`
- **Windows**: Download from [Android SDK Platform Tools](https://developer.android.com/studio/releases/platform-tools)

### 3. Connect your Android device
```bash
adb devices
```

You should see your device listed. If not, enable USB debugging in Developer Options.

## 📖 Usage

### Basic Usage

```bash
python3 Slayer_Log_Security_Scanner_v3.py
```

**Interactive prompts:**
1. Enter package name (e.g., `com.example.app`)
2. Add optional custom keywords/patterns (comma-separated)
3. Ensure app is running and press Enter to detect PID
4. Use the app normally (login, make transactions, browse, etc.)
5. Press **Enter** when testing is complete

### Command Line Arguments

```bash
python3 Slayer_Log_Security_Scanner_v3.py -p com.example.app -l ./reports -s "secret" "token"
```

**Arguments:**
- `-p, --package`: Package name to monitor (e.g., `com.example.app`)
- `-l, --location`: Output directory for reports (default: current directory)
- `-s, --search`: Additional keywords or regex patterns to search for (space-separated)

### Example Workflows

**Banking App Security Audit:**
```bash
python3 Slayer_Log_Security_Scanner_v3.py -p com.bank.mobile -s "account" "balance" "transaction"
```

**E-Commerce App Testing:**
```bash
python3 Slayer_Log_Security_Scanner_v3.py -p com.shop.app -s "cart" "checkout" "payment"
```

**Social Media Privacy Analysis:**
```bash
python3 Slayer_Log_Security_Scanner_v3.py -p com.social.app -l ~/audits/ -s "user_id" "message"
```

## 📊 Output Files

The scanner generates three files:

1. **`logcat_<package>_<timestamp>.txt`**
   - Raw logcat output for reference

2. **`logcat_<package>_<timestamp>_report.html`**
   - **Interactive HTML report** with:
     - 🔍 Real-time search/filter functionality
     - 🎨 Color-coded severity badges
     - 📂 Collapsible sections by finding type
     - 📊 Summary statistics
     - 📝 Line numbers and log tags for each finding

3. **`logcat_<package>_<timestamp>_report.txt`**
   - Plain text report for documentation and archival

## 🎨 Report Features

### Console Output
```
⚠  47 findings  —  12 HIGH  8 MEDIUM  15 LOW  12 ENTROPY

  [HIGH] JWT / Bearer token  (3 hits)
         Line 142: I/OkHttp: Authorization: Bearer eyJhbGciOi...
         Match  : 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'

  [MEDIUM] Transaction ID  (5 hits)
         Line 289: D/PaymentLog: Processing txn_id=TXN202501151430
         Match  : 'TXN202501151430'
```

### HTML Report
- **Searchable findings**: Filter by keywords in real-time
- **Severity badges**: 
  - 🔴 **HIGH** - Immediate attention required
  - 🟡 **MEDIUM** - Review recommended
  - ⚪ **LOW** - Informational, many false positives
  - 🟣 **ENTROPY** - High-entropy tokens detected
- **Grouped findings**: Organized by pattern type for easy navigation
- **Context display**: Shows line numbers and log tags
- **Responsive design**: Works on mobile and desktop browsers

## 🔧 Configuration

### Adjusting Entropy Detection

Modify these constants in the script to tune entropy-based detection:

```python
ENTROPY_THRESHOLD = 3    # Minimum Shannon entropy (0-8 scale)
ENTROPY_MIN_LEN = 20     # Minimum token length to analyze
ENTROPY_MAX_LEN = 500    # Maximum token length to analyze
```

**Recommended values:**
- **More sensitive** (more findings): `ENTROPY_THRESHOLD = 2.5`
- **Less noise** (fewer false positives): `ENTROPY_THRESHOLD = 4.0`

### Adding Custom Patterns

Add your own regex patterns to `SENSITIVE_PATTERNS` list:

```python
("Your Pattern Name", "HIGH",
 re.compile(r'your_regex_pattern', re.I)),
```

**Example - Corporate Employee ID:**
```python
("Employee ID (Company)", "HIGH",
 re.compile(r'EMP\d{6}', re.I)),
```

## 🛡️ Security Considerations

### Philosophy
This tool follows a **"better safe than sorry"** approach:
- ✅ **Broad patterns** - Designed to catch everything
- ✅ **False positives expected** - Human review required
- ✅ **No automated fixes** - Requires security professional judgment
- ✅ **Missing findings is unacceptable** - Better to over-report than miss critical data

### Responsible Use
⚠️ **Important:**
- Only scan applications you **own** or have **explicit permission** to test
- **Secure all report files** - they may contain real sensitive data
- **Delete reports after review** and remediation
- Follow **responsible disclosure** practices for findings
- Comply with applicable **laws and regulations** (GDPR, CCPA, etc.)

### Legal Considerations
- Unauthorized testing may violate:
  - Computer Fraud and Abuse Act (CFAA) in the US
  - Computer Misuse Act in the UK
  - Similar laws in other jurisdictions
- Always obtain **written authorization** before testing third-party applications

## 🐛 Troubleshooting

### Issue: No lines captured

**Symptom:**
```
✓ Capture stopped. 0 lines captured.
⚠  No lines captured. Check package name and that app is running.
```

**Solutions:**
1. Verify the app is running:
   ```bash
   adb shell ps | grep <package>
   ```

2. Check ADB connection:
   ```bash
   adb devices
   ```

3. Ensure USB debugging is enabled on device

4. Try manual logcat first:
   ```bash
   adb logcat | grep <package>
   ```

5. For system apps, use root:
   ```bash
   adb root
   ```

### Issue: Permission denied

**Solutions:**
- Some system apps require root access
- Grant USB debugging permissions on device popup
- Check device is authorized: `adb devices` should show "device", not "unauthorized"

### Issue: Too many false positives

**Solutions:**
1. **Focus on HIGH confidence findings first**
2. **Adjust entropy threshold:**
   ```python
   ENTROPY_THRESHOLD = 4.0  # Increase from default 3.0
   ```
3. **Add safe patterns to exclude:**
   ```python
   ENTROPY_SAFE_RE = re.compile(r'...')  # Add your patterns
   ```
4. **Use custom search patterns** to narrow focus

### Issue: PID not detected

**Symptom:**
```
🔢 PID     : not found — using name filter
⚠  Name filter mode: only lines containing package name captured.
```

**Impact:** You'll miss logs from libraries (OkHttp, Retrofit, WebView) that don't mention the package name.

**Solutions:**
1. Make sure the app is **fully launched** and in foreground
2. Wait a few seconds after opening the app before pressing Enter
3. Check if app is running: `adb shell ps | grep <package>`
4. Some apps have multiple processes - use the main one

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/new-detection-pattern
   ```
3. **Commit your changes**
   ```bash
   git commit -am 'Add detection for X credential type'
   ```
4. **Push to the branch**
   ```bash
   git push origin feature/new-detection-pattern
   ```
5. **Open a Pull Request** with detailed description

### Pattern Contribution Guidelines

When adding new detection patterns:
- ✅ Provide real-world examples of what it matches
- ✅ Specify confidence level (HIGH/MEDIUM/LOW) with reasoning
- ✅ Include at least 3 test cases (should match)
- ✅ Document known false positive scenarios
- ✅ Explain the security impact

### Code Style
- Follow PEP 8 guidelines
- Add comments for complex regex patterns
- Keep functions focused and single-purpose
- Update documentation for user-facing changes

## 📚 Resources & References

### Learning Materials
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [ADB Documentation](https://developer.android.com/studio/command-line/adb)

### Related Tools
- [MobSF (Mobile Security Framework)](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Frida](https://frida.re/) - Dynamic instrumentation toolkit
- [Burp Suite](https://portswigger.net/burp) - Web application security testing

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Slayer**

Security researcher and Android penetration tester.

## 🙏 Acknowledgments

- Android Security community for sharing knowledge
- OWASP Mobile Security Project for best practices
- All contributors and testers who helped improve this tool

## ⚠️ Disclaimer

**This tool is provided for educational and authorized security testing purposes only.**

The author assumes **NO liability** for:
- Misuse of this tool
- Unauthorized access to systems
- Violation of laws or regulations
- Damage caused by this tool

**Users are solely responsible for:**
- Obtaining proper authorization before testing
- Complying with applicable laws and regulations
- Using the tool ethically and responsibly
- Securing any sensitive data discovered during testing

---

<p align="center">
<strong>Made with ❤️ for the Android Security Community</strong><br>
<em>Use responsibly. Test ethically. Secure the mobile ecosystem.</em>
</p>
