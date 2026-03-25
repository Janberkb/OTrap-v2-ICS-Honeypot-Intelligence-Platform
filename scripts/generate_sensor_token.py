#!/usr/bin/env python3
"""
Generate a sensor join token using the running Manager API.
"""

from __future__ import annotations

import os
import sys

import requests


def main() -> int:
    api_base = os.environ.get("API", "http://localhost:8080").rstrip("/")
    admin_user = os.environ.get("ADMIN_USER", "admin")
    admin_pass = os.environ["ADMIN_PASS"]
    sensor_name = os.environ["SENSOR_NAME"]

    session = requests.Session()

    csrf_response = session.get(f"{api_base}/api/v1/auth/csrf-token", timeout=10)
    csrf_response.raise_for_status()
    csrf_token = csrf_response.json()["csrf_token"]

    login_response = session.post(
        f"{api_base}/api/v1/auth/login",
        json={"username": admin_user, "password": admin_pass},
        headers={"X-CSRF-Token": csrf_token},
        timeout=10,
    )
    login_response.raise_for_status()

    csrf_token = session.cookies.get("csrf_token", csrf_token)
    token_response = session.post(
        f"{api_base}/api/v1/sensors/token",
        json={"sensor_name": sensor_name},
        headers={"X-CSRF-Token": csrf_token},
        timeout=10,
    )
    token_response.raise_for_status()
    data = token_response.json()

    print("")
    print(f"Sensor ID:   {data['sensor_id']}")
    print(f"Sensor Name: {data['sensor_name']}")
    print(f"Join Token:  {data['join_token']}")
    print(f"Expires:     {data['expires_at']}")
    print(f"Manager:     {data['manager_addr']}")
    print(f"Image:       {data['sensor_image_ref']}")
    print("")
    if data.get("warnings"):
        print("Warnings:")
        for warning in data["warnings"]:
            print(f"  - {warning}")
        print("")
    print("Remote deploy command:")
    print(data["deployment_command"])
    print("")
    print("Add to .env:")
    print(f"SENSOR_JOIN_TOKEN={data['join_token']}")
    print("")
    print("Advanced .env.sensor snippet:")
    print(data["env_file_snippet"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except requests.HTTPError as exc:
        detail = exc.response.text.strip() if exc.response is not None else str(exc)
        print(f"ERROR: token generation failed: {detail}", file=sys.stderr)
        raise SystemExit(1)
