# Device Compliance

Flask application for uploading device inventory exports, reviewing source
assignments, processing compliance data, and downloading a consolidated Excel
report.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`.

Run the unit and workflow tests with:

```powershell
python -m unittest discover -s tests -v
```

## Deploy to Render

GitHub Pages only serves static files and cannot run this Flask application's
upload, processing, or download routes. The GitHub Actions workflow runs tests
on pushes and pull requests, then triggers a Render deployment after a
successful push to the repository's default branch.

1. Create a Render Web Service for this repository. Use
   `pip install -r requirements.txt` as the build command. The checked-in
   `Procfile` supplies the start command.
2. Set `SECRET_KEY` in the Render service's environment to a unique,
   unpredictable value. For example, generate one locally with
   `python -c "import secrets; print(secrets.token_urlsafe(32))"`. Do not
   commit it.
3. Copy the service's Render Deploy Hook URL.
4. In GitHub, add a repository Actions secret named
   `RENDER_DEPLOY_HOOK_URL` with that URL.
5. Push to the default branch. Tests run first; deployment is triggered only
   when they pass. You can also deploy from the Actions tab with
   `workflow_dispatch`.

## Before using real inventory data

The app currently has no authentication, stores job state in process memory,
and writes uploads and reports to local disk. A Render service is publicly
reachable by default, and local files/job state may not survive a restart or
scale-out. Do not upload sensitive employee or device data until access
controls and durable, appropriately protected storage have been added.