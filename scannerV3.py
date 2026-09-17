import requests
import time
from urllib.parse import urlparse


def scan_website(url):
    try:
        start_time = time.time()

        response = requests.get(url, timeout=10)

        end_time = time.time()

        results = {}

        results["status"] = response.status_code
        results["body"] = response.text
        results["headers"] = response.headers
        results["reason"] = response.reason
        results["final_url"] = response.url
        results["body_length"] = len(response.text)
        results["headers_count"] = len(response.headers)
        results["content_type"] = response.headers.get("Content-Type")
        results["server"] = response.headers.get("Server")

        results["response_time"] = round(
            end_time - start_time, 3
        )

        results["https"] = (
            urlparse(response.url).scheme == "https"
        )

        return results

    except requests.RequestException as error:
        return {"error": str(error)}


target = input("website.com: ")

results = scan_website(target)

if "error" in results:
    print("error:", results["error"])

else:
    print("Status:", results["status"])
    print("Reason:", results["reason"])
    print("Final URL:", results["final_url"])
    print("Response Time:", results["response_time"])
    print("HTTPS:", results["https"])
    print("Server:", results["server"])
    print("Content Type:", results["content_type"])
    print("Body Length:", results["body_length"])
    print("Headers Count:", results["headers_count"])