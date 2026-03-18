import os
import requests
from flask import Blueprint, request
from utils.response import api_response, api_error
from utils.logger import app_logger

chat_bp = Blueprint('chat', __name__)

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY") # Renamed from GOOGLE_API_KEY for clarity

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

SYSTEM_PROMPT = """You are KavachNet Assistant, an AI expert focused on the KavachNet Security Operations Platform. 
KavachNet is a premium, AI-driven Security Operations Center designed to monitor, detect, and neutralize threats in real-time.
Keep your answers brief, professional, and helpful. Guide users to register their institution or log in if they want to access the portal.
"""

@chat_bp.route('/ask', methods=['POST'])
def ask_chat():
    if not OPENROUTER_API_KEY or OPENROUTER_API_KEY == "yourgoogleapikeyhere" or OPENROUTER_API_KEY == "google-api-key-placeholder":
        return api_error("Chat functionality is not fully configured on the server yet.", code=503)

    data = request.get_json()
    if not data or 'message' not in data:
        return api_error("Message is required.", code=400)

    user_message = data['message']
    chat_history = data.get('history', []) # Expects format: [{"role": "user", "content": "..."}, ...]
    
    # Build complete messages list
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    
    # Append limited history (last 5 messages for context)
    valid_history = [m for m in chat_history[-5:] if m.get("role") in ["user", "assistant"] and "content" in m]
    messages.extend(valid_history)
    
    # Add new user message
    messages.append({"role": "user", "content": user_message})

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "HTTP-Referer": "https://kavachnet-frontend.onrender.com", # Required by OpenRouter
        "X-Title": "KavachNet Assistant", # Required by OpenRouter
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "meta-llama/llama-3-8b-instruct:free", # Free tier model suitable for basic chatting
        "messages": messages
    }

    try:
        response = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        
        result_json = response.json()
        ai_reply = result_json['choices'][0]['message']['content']
        
        return api_response(message="Success", data={"reply": ai_reply})
        
    except requests.exceptions.RequestException as e:
        app_logger.error(f"OpenRouter API request failed: {e}")
        return api_error("Sorry, the AI backend is currently unavailable. Please try again later.", code=502)
    except Exception as e:
        app_logger.error(f"Unexpected error in chat endpoint: {e}")
        return api_error("An unexpected error occurred processing your request.", code=500)
