from flask import Flask, request, jsonify
import json

app = Flask(__name__)

@app.route('/payment', methods=['POST'])
def handle_payment():
    try:

        data = request.get_json()
        
        card = json.dumps(data.get('card'), indent=2)
        gateway_config = json.dumps(data.get('gateway_config'), indent=2)

        card_number = card["number"]
        cookies = gateway_config["cookies"]
        
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
