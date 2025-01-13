import os
import uuid
import datetime
from flask import Flask, request, jsonify
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
CORS(app)  # Enable CORS

# Load the JWT_SECRET_KEY from environment variables
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
if not app.config["JWT_SECRET_KEY"]:
    raise RuntimeError("JWT_SECRET_KEY is not set in environment variables!")

# Initialize the JWT Manager
jwt = JWTManager(app)

# Serve the HTML form at the root URL
@app.route("/")
def serve_html():
    return send_from_directory("static", "index.html")

# OpenAI API key from environment variables
openai.api_key = os.getenv("OPENAI_API_KEY")

# Simulated in-memory database (replace with actual database for production)
users = {}  # Store users: {username: {password: hashed_password}}
user_threads = {}  # Store threads: {thread_id: {"user": username, "messages": []}}

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
    email = data.get("email")  # Handle the email field
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password are required"}), 400

    if username in users:
        return jsonify({"success": False, "error": "Username already exists"}), 409

    # Hash the password for secure storage
    hashed_password = generate_password_hash(password)
    users[username] = {"password": hashed_password, "email": email}

    return jsonify({"success": True, "message": "User registered successfully"}), 201



@app.route("/login", methods=["POST"])
def login():
    """
    Authenticate user and return a JWT token.
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Validate username and password
    user = users.get(username)
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Generate a JWT token
    token = create_access_token(identity=username)
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
    return jsonify({"thread_id": thread_id})


@app.route("/threads", methods=["GET"])
@jwt_required()
def get_threads():
    """
    Get all threads for the authenticated user.
    """
    user = get_jwt_identity()
    threads = {k: v for k, v in user_threads.items() if v["user"] == user}
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

    if thread_id not in user_threads:
        return jsonify({"error": "Invalid thread ID"}), 404

    # Add user message to thread
    user_threads[thread_id]["messages"].append({"role": "user", "content": question})

    # Prepare messages for OpenAI
    messages = [{"role": "system", "content": "You are an Islamic assistant."}]
    messages += user_threads[thread_id]["messages"]

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=messages,
            temperature=0.7,
        )
        assistant_reply = response.choices[0].message["content"]

        # Add assistant message to thread
        user_threads[thread_id]["messages"].append({"role": "assistant", "content": assistant_reply})

        return jsonify({"success": True, "reply": assistant_reply})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


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
