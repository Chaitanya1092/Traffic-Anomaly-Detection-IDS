"""Build the fictional-data demo as static files for GitHub Pages."""

import json
import shutil
from pathlib import Path

from public_demo import app


ROOT = Path(__file__).resolve().parent
SITE = ROOT / "docs"
PAGE_ROUTES = {
    "/": "index.html",
    "/alerts": "alerts.html",
    "/stats": "stats.html",
    "/devices": "devices.html",
}
STATIC_LINKS = {
    'href="/"': 'href="./index.html"',
    'href="/alerts"': 'href="./alerts.html"',
    'href="/stats"': 'href="./stats.html"',
    'href="/devices"': 'href="./devices.html"',
    'href="/api/alerts/export"': 'href="./demo-data/alerts.csv"',
    'href="/static/': 'href="./static/',
    'src="/static/': 'src="./static/',
}


def write_response(path, content):
    destination = SITE / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)


def build():
    client = app.test_client()
    SITE.mkdir(parents=True, exist_ok=True)

    for route, filename in PAGE_ROUTES.items():
        response = client.get(route)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to render {route}: HTTP {response.status_code}")
        html = response.get_data(as_text=True)
        for old, new in STATIC_LINKS.items():
            html = html.replace(old, new)
        html = html.replace(
            '<body data-read-only="true">',
            '<body data-read-only="true" data-static-demo="true" data-base-path="./">',
        )
        if 'data-static-demo="true"' not in html:
            raise RuntimeError(f"Static demo configuration was not added to {filename}")
        write_response(filename, html.encode("utf-8"))

    (SITE / "static" / "css").mkdir(parents=True, exist_ok=True)
    (SITE / "static" / "js").mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "static" / "css" / "style.css", SITE / "static" / "css" / "style.css")
    shutil.copy2(ROOT / "static" / "js" / "dashboard.js", SITE / "static" / "js" / "dashboard.js")

    data_files = {
        "status.json": "/api/status",
        "stats.json": "/api/stats?limit=120",
        "alerts.json": "/api/alerts?limit=100",
        "logs.json": "/api/logs?limit=50",
        "devices.json": "/api/devices",
    }
    for filename, route in data_files.items():
        response = client.get(route)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to build sample data {route}: HTTP {response.status_code}")
        payload = json.loads(response.get_data(as_text=True))
        write_response(
            Path("demo-data") / filename,
            json.dumps(payload, indent=2).encode("utf-8"),
        )

    csv_response = client.get("/api/alerts/export")
    if csv_response.status_code != 200:
        raise RuntimeError("Failed to build sample alerts CSV")
    write_response(Path("demo-data") / "alerts.csv", csv_response.get_data())

    write_response(
        ".nojekyll",
        b"",
    )
    print(f"Built public sample demo in {SITE}")


if __name__ == "__main__":
    build()
