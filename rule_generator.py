from google import genai
from google.genai import types
import json
import uuid
import os


API_KEY = os.getenv("GOOGLE_API_KEY", "XXXXXXXXXX")

def generate_yara_rule(artefact):
    """
    Generates a YARA rule based on the provided artefact using the new Google Gen AI SDK.
    """
    
    # Initialize the client
    client = genai.Client(api_key=API_KEY)

    prompt = f"""
    You are a cybersecurity detection engineer.
    Given the following artefact characteristics, generate a YARA rule
    to detect future malicious files exhibiting similar behaviour.

    Artefact summary:
    {json.dumps(artefact, indent=2)}

    Constraints:
    - Output ONLY valid YARA code
    - No hashes
    - Generalise behaviour
    - Do not use markdown formatting (no backticks)
    """

    try:
        # Generate content
        # Note: 'contents' replaces the old prompt argument
        # 'config' replaces 'generation_config'
        response = client.models.generate_content(
            model='gemini-flash-latest',  # Recommended: Faster & smarter than 1.5
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2
            )
        )

        # Extract text
        rule = response.text
        
        # Safety cleanup (in case the model still adds markdown wrappers)
        rule = rule.replace("```yara", "").replace("```", "").strip()

        rule_id = str(uuid.uuid4())
        return rule_id, rule

    except Exception as e:
        return None, f"Error generating rule: {str(e)}"

if __name__ == "__main__":
    # Ensure artefact.json exists for testing
    if not os.path.exists("artefact.json"):
        dummy_data = {
            "strings": ["CreateRemoteThread", "VirtualAllocEx", "powershell -enc"],
            "imports": ["kernel32.dll", "user32.dll"],
            "file_type": "PE32"
        }
        with open("artefact.json", "w") as f:
            json.dump(dummy_data, f)
        print("Note: Created dummy artefact.json for testing...")

    try:
        with open("artefact.json", "r") as f:
            artefact = json.load(f)
            
        rid, rule = generate_yara_rule(artefact)
        
        if rid:
            print(f"// Generated Rule ID: {rid}")
            print(rule)
        else:
            print(rule) # Prints error message
            
    except FileNotFoundError:
        print("Error: artefact.json not found.")
