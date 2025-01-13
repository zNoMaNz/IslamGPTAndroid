import os
import uuid
import logging
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from werkzeug.security import generate_password_hash, check_password_hash
import openai

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Load environment variables
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "default_secret_key")  # Default for dev
openai.api_key = os.getenv("OPENAI_API_KEY")

# Logging configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Simulated in-memory database (replace with actual database for production)
users = {}
user_threads = {}

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)


# ---------------------
# Authentication Routes
# ---------------------

@app.route("/register", methods=["POST"])
def register():
    """
    Register a new user.
    """
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password are required"}), 400

    if username in users:
        return jsonify({"success": False, "error": "Username already exists"}), 409

    users[username] = {"password": generate_password_hash(password), "email": email}
    logging.info("User registered: %s", username)
    return jsonify({"success": True, "message": "User registered successfully"}), 201


@app.route("/login", methods=["POST"])
def login():
    """
    Authenticate user and return a JWT token.
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = users.get(username)
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=username)
    logging.info("User logged in: %s", username)
    return jsonify({"token": token})


# ---------------------
# Thread Management Routes
# ---------------------

@app.route("/thread", methods=["POST"])
@jwt_required()
def create_thread():
    """
    Create a new conversation thread.
    """
    thread_id = str(uuid.uuid4())
    user = get_jwt_identity()
    user_threads[thread_id] = {"user": user, "messages": []}
    logging.info("Thread created: %s by user: %s", thread_id, user)
    return jsonify({"thread_id": thread_id})


@app.route("/threads", methods=["GET"])
@jwt_required()
def get_threads():
    """
    Get all threads for the authenticated user.
    """
    user = get_jwt_identity()
    threads = {k: v for k, v in user_threads.items() if v["user"] == user}
    logging.info("Threads retrieved for user: %s", user)
    return jsonify(list(threads.keys()))


# ---------------------
# Chat Routes
# ---------------------

@app.route("/ask", methods=["POST"])
@jwt_required()
def ask():
    """
    Handle user messages and respond using OpenAI Chat API.
    """
    data = request.get_json()
    thread_id = data.get("thread_id")
    question = data.get("question", "").strip()

    if not thread_id or thread_id not in user_threads:
        return jsonify({"error": "Invalid thread ID"}), 404

    user_threads[thread_id]["messages"].append({"role": "user", "content": question})

    messages = [{"role": "system", "content": "You are an Islamic assistant."}]
    messages += user_threads[thread_id]["messages"]

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=messages,
            temperature=0.7,
        )
        assistant_reply = response.choices[0].message["content"]
        user_threads[thread_id]["messages"].append({"role": "assistant", "content": assistant_reply})
        logging.info("Response generated for thread: %s", thread_id)
        return jsonify({"success": True, "reply": assistant_reply})
    except Exception as e:
        logging.error("Error in OpenAI API call: %s", e)
        return jsonify({"success": False, "error": "Failed to fetch response from AI"}), 500


# ---------------------
# Utility Routes
# ---------------------

@app.route("/health", methods=["GET"])
def health_check():
    """
    Health check endpoint for monitoring.
    """
    return jsonify({"status": "ok"})


# ---------------------
# Run the Flask App
# ---------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
