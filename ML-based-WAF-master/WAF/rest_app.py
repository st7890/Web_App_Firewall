from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/srs/api/hello/test', methods=['GET','POST'])  # Define the route with POST method
def hello_test():
    try:
        data = request.json  # Get JSON data from the request
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # You can add your processing logic here
        return jsonify({'success': True, 'received': data}), 200  # Successful response
    except Exception as e:
        return jsonify({'error': str(e)}), 500  # Catch any exceptions

if __name__ == '__main__':
    app.run(debug=True)  # Run the app in debug mode
