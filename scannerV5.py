import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs


security_headers = {
    "Content-Security-Policy": "Content-Security-Policy",
    "Strict-Transport-Security": "Strict-Transport-Security",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Referrer-Policy": "Referrer-Policy"
}


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

        results["security_headers"] = {}
        results["findings"] = []

        for header, name in security_headers.items():
            if header in response.headers:
                results["security_headers"][name] = "Found"
            else:
                results["security_headers"][name] = "Missing"

                results["findings"].append({
                    "type": "Missing Security Header",
                    "header": name
                })

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        title = soup.title

        if title:
            results["title"] = title.get_text(strip=True)
        else:
            results["title"] = "No title"

        results["links"] = []

        for link in soup.find_all("a", href=True):
            full_url = urljoin(
                response.url,
                link["href"]
            )

            results["links"].append(full_url)

        # URL Parameters
        results["parameters"] = []

        for link in results["links"]:
            parsed_url = urlparse(link)
            parameters = parse_qs(parsed_url.query)

            for parameter in parameters:
                results["parameters"].append(parameter)

        results["forms"] = []

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()

            form_url = urljoin(
                response.url,
                action
            )

            results["forms"].append({
                "action": form_url,
                "method": method
            })

        robots_url = urljoin(
            response.url,
            "/robots.txt"
        )

        robots_response = requests.get(
            robots_url,
            timeout=10
        )

        results["robots_txt"] = (
            robots_response.status_code == 200
        )

        sitemap_url = urljoin(
            response.url,
            "/sitemap.xml"
        )

        sitemap_response = requests.get(
            sitemap_url,
            timeout=10
        )

        results["sitemap_xml"] = (
            sitemap_response.status_code == 200
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

    print("Security Headers")

    for name, status in results["security_headers"].items():
        print(name, ":", status)

    print("Findings")

    for finding in results["findings"]:
        print(finding["type"], ":", finding["header"])

    print("Title:", results["title"])

    print("Total Links:", len(results["links"]))

    for link in results["links"]:
        print(link)

    print("Parameters:", len(results["parameters"]))

    for parameter in results["parameters"]:
        print(parameter)

    print("Total Forms:", len(results["forms"]))

    for form in results["forms"]:
        print("Action:", form["action"])
        print("Method:", form["method"])

    print("robots.txt:", results["robots_txt"])
    print("sitemap.xml:", results["sitemap_xml"])