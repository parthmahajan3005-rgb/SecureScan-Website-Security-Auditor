# SecureScan — Automated Website Security Auditor

## Project description
SecureScan is a beginner-friendly Python cybersecurity project that performs a lightweight check of HTTPS usage and six common HTTP response security headers:
- Strict-Transport-Security
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy

It prints a summary with an educational score and exports individual findings to `securescan_report.csv`.

## Technologies used
- Python 3.10+
- `requests` for making a single HTTP request
- Python standard library: `urllib.parse`, `ipaddress`, `socket`, `csv`, and `datetime`
- Jupyter Notebook (for the `.ipynb` submission)

## Dataset
**No external dataset is required.** The project checks live HTTP response headers from a user-provided, authorized website. The output is generated dynamically at scan time. For a demonstration, use a website you own or have permission to assess; `https://example.com` may be used to verify basic operation, but it is not a security benchmark.

## Setup
1. Install Python 3.10 or newer.
2. Download the project files into one folder.
3. (Recommended) Create and activate a virtual environment:
   - Windows: `python -m venv .venv` then `.venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Run as a Python script
```bash
python Parth_Mahajan_SecureScan.py
```
Enter a public website URL you own or are authorized to test when prompted. The program prints the findings and saves `securescan_report.csv`.

## Run as a Jupyter Notebook
1. Start Jupyter Notebook or JupyterLab.
2. Open `Parth_Mahajan_SecureScan.ipynb`.
3. Run the cells from top to bottom.
4. Enter an authorized public website URL in the final execution cell.

## Methodology
1. Validate the URL and restrict protocols to HTTP/HTTPS.
2. Resolve the host and block localhost/private/reserved IP addresses.
3. Make one request with a timeout and follow redirects.
4. Check HTTPS and whether the selected security headers are present.
5. Calculate a simple educational score and export findings to CSV.

## Limitations
- Header presence alone does not prove a header is configured correctly.
- The score is illustrative and is not an industry-standard rating.
- This tool does not scan ports, exploit vulnerabilities, or test application logic.
- Network restrictions, redirects, DNS configuration, and server responses can affect results.
- The scanner is designed for educational, low-impact use only.

## Responsible use
Scan only websites you own or have explicit authorization to assess. Do not use the tool to disrupt services or access private systems.
