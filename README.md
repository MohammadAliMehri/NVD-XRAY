# NVD-XRAY

NVD-XRAY is a small, inspectable Python CLI agent that queries the NVD CVE API 2.0 and returns a Pydantic-validated vulnerability brief. It currently uses NVIDIA's OpenAI-compatible endpoint with `nvidia/nemotron-3.5-super-vl-120b-a12b`.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set `NVIDIA_API_KEY` in `.env`. `NVD_API_KEY` is optional. Do not commit `.env`.

## Run

```powershell
python main.py --cve-id CVE-2021-44228
python main.py --query "Apache Log4j remote code execution"
```

By default, the CLI prints the model's tool selection, returned tool data, and the final validated report. Use `--hide-trace` for report-only output.

## Behavior

- Exact CVE identifiers use `get_cve_details`.
- Other requests use bounded `search_cves` results.
- NVD is the fact source; inferred guidance is labeled separately through the system prompt and report fields.
- Missing scores, versions, patches, or references remain unknown or empty.
- Timeouts, NVD rate limits, and transient server failures use bounded retries.

## Test

```powershell
python -m unittest discover -s tests -v
```

## MVP Definition of Done

A user can search NVD by CVE ID or keyword, observe the agent's tool call and result, and receive a source-linked, schema-valid brief that separates verified NVD fields, defensive guidance, and unknowns.
