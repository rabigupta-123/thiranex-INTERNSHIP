# Password Strength Analyzer

A Flask web app and command-line tool for evaluating password length, complexity, entropy, reuse, and estimated brute-force resistance.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in a browser.

## Test

```powershell
python -m unittest test_analyzer test_app -v
```

The SQLite history database is created locally as `passwords.db` and is ignored by Git.