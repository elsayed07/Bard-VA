'''from typing import Any
from typing import Optional

import requests


def geoip(key: Optional[str], target: str) -> Any:
    if key is None:
        raise ValueError("KeyNotFound: Key Not Provided")
    #assert key is not None  # This will help the type checker
    if target is None:
        raise ValueError("InvalidTarget: Target Not Provided")
    #url = f"https://api.ipgeolocation.io/ipgeo?apiKey={key}&ip={target}"
    url = f"http://ip-api.com/json/{target}"
    response = requests.get(url)
    content = response.text
    return content'''
    
import requests
from typing import Any, Optional

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

