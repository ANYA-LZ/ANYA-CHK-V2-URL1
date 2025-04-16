from flask import Flask, request, jsonify
from faker import Faker
import requests
import random
from urllib.parse import urlparse
import json
from lxml import html

app = Flask(__name__)

fake = Faker("en_US")
domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]

def fetch_city_zipcode_data():
    url = "https://raw.githubusercontent.com/AbderrezakLzone/country-map/refs/heads/main/US/state.json"
    try:
        response = requests.get(url)

        if response.status_code == 200:
            return response.json()
        else:
            return False
    except requests.exceptions.RequestException as e:
        return False

def generate_random_person():
    city_zipcode_data = fetch_city_zipcode_data()
    if not city_zipcode_data:
        return False

    state_name = random.choice(list(city_zipcode_data.keys()))
    city_name = random.choice(list(city_zipcode_data[state_name].keys()))
    zipcode = city_zipcode_data[state_name][city_name]
    
    phone = fake.phone_number()

    phone = phone.replace("(", "").replace(")", "").replace(" ", "").replace("-", "")
    if phone[:3] != zipcode[:3]:
        phone = f"({zipcode[:3]})-{phone[3:6]}-{phone[6:]}"

    return {
        'firstname': fake.first_name(),
        'lastname': fake.last_name(),
        'username': fake.user_name()[:10],
        'password': fake.password(),
        'email': f"{fake.user_name()[:10]}@{random.choice(domains)}",
        'phone': phone,
        'city': city_name,
        'country': "United States",
        'state': state_name,
        'zipcode': zipcode,
        'address': fake.street_address(),
        'useragent': fake.user_agent(),
    }
    
def get_nonce(cookies, random_person, url):
    url_parse = urlparse(url)
    params = {'_wc_user_reg': "true"}
    headers = {
        'User-Agent': random_person['useragent'],
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': url_parse,
        'referer': url,
    }

    try:
        with requests.Session() as session:
            session.headers.update(headers)
            response = session.post(url, params=params, cookies=cookies, timeout=10).content
            
        tree = html.fromstring(response)
        nonce_value = tree.xpath('//input[@id="woocommerce-add-payment-method-nonce"]/@value')
        return nonce_value[0] if nonce_value else None
    except requests.Timeout:
        return False
    except Exception as e:
        return False

@app.route('/payment', methods=['POST'])
def handle_payment():
    try:
        data = request.get_json()
        
        card = data.get('card')
        if not card:
            return jsonify({"status": "error", "message": "Card information is missing"}), 400
        
        gateway_config = data.get('gateway_config')
        if not gateway_config:
            return jsonify({"status": "error", "message": "Gateway configuration is missing"}), 400
        
        random_person = generate_random_person()
        if not random_person:
            return jsonify({"status": "error", "message": "Failed to generate random person"}), 400
        
        cookies = gateway_config.get("cookies")
        if not cookies:
            return jsonify({"status": "error", "message": "Cookies are missing in gateway config"}), 400
        
        cookies_dict = {cookie["name"]: cookie["value"] for cookie in gateway_config["cookies"]}

        url = gateway_config.get("url")
        if not url:
            return jsonify({"status": "error", "message": "url are missing in gateway config"}), 400

        nonce = get_nonce(cookies_dict, random_person, url)
        if not nonce:
            return jsonify({"status": "error", "message": "Failed to fetch nonce"}), 400

        card_number = card.get("number")
        if not card_number:
            return jsonify({"status": "error", "message": "Card number is missing"}), 400
        
        return jsonify({
            "status": "success",
            "message": "Payment processed successfully",
            "card": card_number,
            "cookies": nonce
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
