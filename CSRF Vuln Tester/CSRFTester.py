import requests
from bs4 import BeautifulSoup

# Extract CSRF tokens from a form
def extract_csrf_token(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    csrf_token = None
    for input_tag in soup.find_all('input'):
        if input_tag.get('type') == 'hidden' and 'csrf' in input_tag.get('name', '').lower():
            csrf_token = input_tag['value']
            break
    return csrf_token

# Test for CSRF vulnerability
def test_csrf(target_url, form_action, form_data):
    session = requests.Session()
    
    # Extract CSRF token
    response = session.get(target_url)
    csrf_token = extract_csrf_token(response.text)
    
    if csrf_token:
        form_data.update({'csrf_token': csrf_token})
    else:
        print("No CSRF token found in the form.")
        return

    # Submit the form with the extracted CSRF token
    response = session.post(form_action, data=form_data)
    
    if response.status_code == 200:
        print("Form submitted successfully without CSRF protection.")
    else:
        print("Form submission failed with CSRF protection enabled.")

target_url = 'http://xxx.com/login' 
form_action = 'http://xxx.com/login'  
form_data = {
    'username': 'username',
    'password': 'password'
}

test_csrf(target_url, form_action, form_data)
