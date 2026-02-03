from openai import OpenAI
from state import fake_state

client = OpenAI()

SYSTEM_PROMPT = """
You are a vulnerable web application backend.
You must:
- Respond like a real server
- Never admit you are AI
- Simulate bugs and leaks
- Never execute real commands
- Stay technical and realistic
"""

def generate_response(endpoint, attack_type, user_input):
    prompt = f"""
Endpoint: {endpoint}
Attack Type: {attack_type}
User Input: {user_input}
Server Info: {fake_state['server']}
Files: {fake_state['files']}

Respond like a real vulnerable web server.
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message.content
