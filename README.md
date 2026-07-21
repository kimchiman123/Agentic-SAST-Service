# Agentic SAST Guardian

Local Streamlit interface for Semgrep, dependency scanning, LLM-assisted security review, and PDF/HTML, XLSX, and JSON reports.

## Run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

`python main.py` is the only application entrypoint. It starts a localhost-only Streamlit child process with XSRF and CORS protections from `.streamlit/config.toml`.

## Input and privacy

- Select one local project directory, one ZIP project, or multiple loose source files.
- Uploads are extracted into a per-run temporary workspace. Traversal paths, nested ZIP files, links, special files, path collisions, Windows reserved names, and configured size/count limits are rejected before analysis.
- The UI key field is an in-memory, single-run override. It is not saved to `.env`, reports, events, or work logs.
- A configured `OPENAI_API_KEY` or `NVIDIA_API_KEY` may be loaded from `.env`. Copy `.env.example` to begin.

## Runtime configuration

Environment values are parsed strictly at startup. Defaults include an 8-item / 24,000-character batch limit, 25 MiB upload limit, and a single active scan per process.

| Setting | Default |
| --- | ---: |
| `SAST_BATCH_MAX_ITEMS` | 8 |
| `SAST_BATCH_MAX_CHARS` | 24000 |
| `SAST_BATCH_INPUT_TOKENS` | 12000 |
| `SAST_BATCH_OUTPUT_TOKENS` | 4000 |
| `SAST_UPLOAD_MAX_MIB` | 25 |
| `SAST_UPLOAD_FILE_MAX_MIB` | 2 |
| `SAST_UPLOAD_MAX_FILES` | 500 |
| `SAST_UPLOAD_EXTRACTED_MAX_MIB` | 100 |

## Verification

```powershell
python -m pytest -m "not live_nvidia"
```

The opt-in `live_nvidia` tests require a real NVIDIA key and are skipped by default. Docker Desktop is required for the Semgrep scan stage.
