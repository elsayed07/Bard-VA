import requests
from typing import Any

def geoip(key: str, target: str) -> str:
    if not key:
        raise ValueError("KeyNotFound: Key Not Provided")
    if not target:
        raise ValueError("InvalidTarget: Target Not Provided")

    url = f"http://ip-api.com/json/{target}"
    response = requests.get(url)

    if response.status_code == 200:
        content = response.text
        return content
    else:
        print("Error: Unable to fetch geoip data. Status Code:", response.status_code)
        return "None"

