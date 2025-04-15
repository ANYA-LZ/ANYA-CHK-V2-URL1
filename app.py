from flask import Flask, request, jsonify
import json

app = Flask(__name__)

@app.route('/payment', methods=['POST'])
def handle_payment():
    try:
        data = request.get_json()
        
        # Get the card and gateway_config from the data
        card = data.get('card')
        gateway_config = data.get('gateway_config')
        
        # Check if card and gateway_config are present
        if not card:
            return jsonify({"status": "error", "message": "Card information is missing"}), 400
        if not gateway_config:
            return jsonify({"status": "error", "message": "Gateway configuration is missing"}), 400
        
        # Extract required fields
        card_number = card.get("number")
        cookies = gateway_config.get("cookies")
        
        # Check if required fields are present within card and gateway_config
        if not card_number:
            return jsonify({"status": "error", "message": "Card number is missing"}), 400
        if not cookies:
            return jsonify({"status": "error", "message": "Cookies are missing in gateway config"}), 400
        
        return jsonify({
            "status": "success",
            "message": "Payment processed successfully",
            "card": card_number,
            "cookies": cookies
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
