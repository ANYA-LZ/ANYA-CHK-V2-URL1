from flask import Flask, request, jsonify
import json

app = Flask(__name__)

@app.route('/', methods=['POST'])
def handle_payment():
    try:

        data = request.get_json()
        
        print("Received payment request:")
        print("Gateway Data:", json.dumps(data.get('gateway_config'), indent=2))
        print("Card Info:", json.dumps(data.get('card'), indent=2))
        
        
        return jsonify({
            "status": "success",
            "message": "Payment processed successfully",
            "received_data": data
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
