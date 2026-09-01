# Kaggle AI Agent Security

Repository for the Kaggle competition:

**AI Agent Security - Multi-Step Tool Attacks**

## Project Structure

- `attack.py`
- `data/`
  - `aicomp_sdk/`
- `notebooks/`
- `src/`
- `tests/`
- `outputs/`
- `requirements.txt`

## Local Development and Testing

### Requirements

- Python 3.12

### Create a Virtual Environment

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS/Linux/WSL:

```bash
source .venv/bin/activate
```

### Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### Configure the SDK Path

The SDK package is located at `data/aicomp_sdk`. Add `data` to `PYTHONPATH`.

Windows PowerShell:

```powershell
$env:PYTHONPATH = "$PWD\\data"
```

macOS/Linux/WSL:

```bash
export PYTHONPATH="$PWD/data"
```

### Test the SDK Import

```bash
python -c "import aicomp_sdk; print('SDK OK')"
```

### Validate `attack.py`

```bash
python -m aicomp_sdk.cli.main validate redteam attack.py
```

### Run the Local Red-Team Test

```bash
python -m aicomp_sdk.cli.main test redteam attack.py
```

### Test Results

```text
.aicomp/history/
```

### Git Notes

Do not commit:

- `.venv/`
- `.aicomp/history/`
- `evaluation_artifacts/`
