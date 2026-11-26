# NVD-XRAY

NVD-XRAY is a production-oriented vulnerability research console for NVD CVE API 2.0. It provides a responsive Flask web interface and a clean command-line report, backed by NVIDIA's OpenAI-compatible model endpoint and Pydantic validation.

## Capabilities

- Research an exact CVE identifier or search NVD by product and vulnerability keyword.
- Display severity, CVSS, affected products, remediation, security guidance, limitations, and references.
- Keep NVD evidence separate from model-generated defensive guidance.
- Preserve unknown values instead of fabricating scores, versions, or patches.
- Export validated reports as JSON from the web console.
- Retry bounded NVD timeout, rate-limit, and transient server failures.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set `NVIDIA_API_KEY` in `.env`. An `NVD_API_KEY` is optional but recommended for higher NVD request limits. Never commit `.env`.

## Web Console

Run the development server:

```powershell
python app.py
```

Run with the production WSGI server:

```powershell
waitress-serve --host=127.0.0.1 --port=5000 app:app
```

Open `http://127.0.0.1:5000`. The health check is available at `http://127.0.0.1:5000/health`.

## Command Line

```powershell
python main.py --cve-id CVE-2021-44228
python main.py --query "Apache Log4j remote code execution"
python main.py --cve-id CVE-2021-44228 --json
python main.py --cve-id CVE-2021-44228 --trace
```

The default CLI format is a readable terminal report. Use `--json` for automation and `--trace` for tool-call debugging.

## Environment

```text
NVIDIA_API_KEY=...
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
NVIDIA_MODEL=nvidia/nemotron-3.5-super-vl-120b-a12b
NVIDIA_TIMEOUT_SECONDS=60
NVD_API_KEY=
NVD_TIMEOUT_SECONDS=20
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=false
```

For internet-facing deployment, place the WSGI server behind TLS, authentication, request-rate controls, and a secrets manager.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Runtime Requirements

- Python 3.11 or newer
- NVIDIA API credentials
- Outbound HTTPS access to NVD and the configured NVIDIA endpoint
