import requests
import os
from pathlib import Path
from dotenv import load_dotenv

# Buscar el .env en la raíz del proyecto
project_root = Path(__file__).parent.parent.parent
env_path = project_root / '.env'

print(f"🔍 Buscando .env en: {env_path}")

if env_path.exists():
    load_dotenv(env_path)
    print("✅ .env cargado desde la raíz del proyecto")
else:
    load_dotenv()
    print("⚠️  Cargando .env desde ubicación actual")

api_key = os.environ.get('DEEPSEEK_API_KEY')

print("=" * 50)
print("🔍 VERIFICACIÓN COMPLETA")
print("=" * 50)

if not api_key:
    print("❌ ERROR: No se encontró DEEPSEEK_API_KEY")
    print("   El archivo .env debe estar en la raíz del proyecto")
    print("   Ruta esperada:", project_root / '.env')
    exit()

print(f"✅ API Key cargada: {api_key[:15]}...")

url = "https://api.deepseek.com/v1/chat/completions"
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

data = {
    "model": "deepseek-chat",
    "messages": [
        {
            "role": "user", 
            "content": "Responde solo con '✅ CHATBOT FUNCIONANDO' si esto funciona"
        }
    ],
    "max_tokens": 10
}

try:
    print("🔄 Probando API de DeepSeek...")
    response = requests.post(url, headers=headers, json=data, timeout=30)
    
    print(f"📊 Status Code: {response.status_code}")
    
    if response.status_code == 200:
        result = response.json()
        bot_response = result['choices'][0]['message']['content']
        print("🎉 ¡ÉXITO! ✅ ✅ ✅")
        print(f"🤖 Respuesta: {bot_response}")
        print("\n✨ ¡Tu chatbot está listo para usar!")
    else:
        print(f"❌ Error {response.status_code}: {response.text}")
        
except Exception as e:
    print(f"💥 Error: {e}")