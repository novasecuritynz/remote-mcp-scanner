import httpx
from .colors import error

def post_json(url, json_data):
    try:
        return httpx.post(url, json=json_data, timeout=10)
    except Exception as e:
        print(error(f"Request failed: {e}"))
        return None

def get_text(url):
    try:
        return httpx.get(url, timeout=10).text
    except Exception as e:
        print(error(f"GET failed: {e}"))
        return ""

def get_json(url):
    """Get JSON response from URL, returns (status_code, json_data) tuple"""
    try:
        response = httpx.get(url, timeout=10)
        if response.status_code == 200:
            try:
                return response.status_code, response.json()
            except ValueError:
                print(error(f"Invalid JSON response from {url}"))
                return response.status_code, None
        else:
            return response.status_code, None
    except Exception as e:
        print(error(f"GET failed: {e}"))
        return None, None
