import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
from analyzer import HandwritingAnalyzer

# Initialize the Flask application
app = Flask(__name__)

# --- Configuration ---
# Allow requests from your React app's origin (e.g., http://localhost:5173)
# The "*" allows all origins for simplicity during development.
CORS(app) 
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Create the folder if it doesn't exist
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Load the Analyzer ---
# This is important! We load the models only once when the server starts.
print("Initializing the handwriting analyzer...")
MODELS_PATH = 'models'
try:
    handwriting_analyzer = HandwritingAnalyzer(MODELS_PATH)
    print("Analyzer initialized successfully.")
except Exception as e:
    print(f"FATAL: Could not initialize HandwritingAnalyzer. Error: {e}")
    handwriting_analyzer = None

# --- API Route ---
@app.route('/analyze', methods=['POST'])
def analyze_image():
    if handwriting_analyzer is None:
        return jsonify({"error": "Analyzer is not available due to an initialization error."}), 500

    # Check if a file was sent in the request
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    if file:
        # Save the uploaded file to a temporary location
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            # --- Perform the analysis ---
            result = handwriting_analyzer.analyze(filepath)
            # Clean up the temporary file
            os.remove(filepath)
            # Return the result as JSON
            return jsonify(result)
        except Exception as e:
            # Clean up even if there's an error
            if os.path.exists(filepath):
                os.remove(filepath)
            print(f"An error occurred during analysis: {e}")
            return jsonify({"error": f"An internal error occurred: {e}"}), 500

    return jsonify({"error": "An unknown error occurred"}), 500

# --- Start the Server ---
if __name__ == '__main__':
    # We use port 5001 to avoid conflicts with other servers (like your React app)
    app.run(host='0.0.0.0', port=5001, debug=True)