import datetime
import json
import os
from os import path
import requests
from dotenv import load_dotenv

load_dotenv()

# Script para postar eventos no Microsoft Teams
SIEM_KEY = os.getenv("SIEM_KEY")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")
SIEM_URL = os.getenv("SIEM_URL")

# Verifica se as variáveis de ambiente foram carregadas corretamente
if not all([SIEM_KEY, TEAMS_WEBHOOK_URL, SIEM_URL]):
   raise ValueError("As variáveis de ambiente não foram carregadas corretamente. Verifique o arquivo .env.")

def post_to_teams(message):
   headers = {'Content-Type': 'application/json'}
   data = {
       "@type": "MessageCard",
       "@context": "http://schema.org/extensions",
       "title": "Alerta de Segurança QRadar",
       "text": message
   }
   try:
       response = requests.post(TEAMS_WEBHOOK_URL, headers=headers, data=json.dumps(data))
       response.raise_for_status()
       return response.json()
   except requests.RequestException as e:
       print(f"Erro ao enviar mensagem para o Teams: {e}")
       return None


def get_severity_appearance(severity):
   """Representa visualmente a severidade da ofensa com barras coloridas."""
   if severity <= 2:
       return "Low Severity: 🟨🟨⬜️⬜️⬜️⬜️"
   elif severity <= 4:
       return "Moderate Severity: 🟧🟧🟧⬜️⬜️⬜️"
   elif severity <= 6:
       return "High Severity: 🟥🟥🟥🟥⬜️⬜️"
   elif severity <= 8:
       return "Very High Severity: 🟥🟥🟥🟥🟥⬜️"
   return "Critical Severity: 🟪🟪🟪🟪🟪🟪"

def get_siem_offenses():
   """Função para buscar ofensas do SIEM."""
   headers = {
       'SEC': SIEM_KEY,
       'Accept': 'application/json',
       'Content-Type': 'application/json'
   }
   try:
       response = requests.get(f'{SIEM_URL}api/siem/offenses', headers=headers, params={"filter": "status=OPEN"}, verify=True)
       response.raise_for_status()
       return response.json()
   except requests.RequestException as e:
       print(f"Erro ao buscar ofensas do SIEM: {e}")
       return []

def create_offense_for_teams(raw_offense):
   time = datetime.datetime.fromtimestamp(raw_offense['start_time'] / 1000.0).strftime('%Y-%m-%d %H:%M:%S')
   offense_url = f"{SIEM_URL}console/qradar/jsp/QRadar.jsp?appName=Sem&pageId=OffenseSummary&summaryId={raw_offense['id']}"
   return f"**Offense ID**: {raw_offense['id']}  \n" \
          f"**Description**: {raw_offense['description'].replace('\\n', ' ')}  \n" \
          f"**Time**: {time}  \n" \
          f"**Category**: {raw_offense.get('categories', 'N/A')}  \n" \
          f"**Offense Source**: {raw_offense.get('offense_source', 'N/A')}  \n" \
          f"**Source Network**: {raw_offense.get('source_network', 'N/A')}  \n" \
          f"**Destination Networks**: {raw_offense.get('destination_networks', 'N/A')}  \n" \
          f"**Severity**: {get_severity_appearance(raw_offense['severity'])}  \n" \
          f"**URL**: [Click here]({offense_url})"



def load_cache(filename='cache.json'):
   """Carrega o cache de IDs já enviados."""
   if not path.exists(filename):
       return set()
   with open(filename, 'r') as f:
       return set(json.load(f))
   
def save_cache(cache, filename='cache.json'):
   """Salva o cache de IDs no arquivo."""
   with open(filename, 'w') as f:
       json.dump(list(cache), f)

if __name__ == '__main__':
   sent_offenses_cache = load_cache()
   offenses = get_siem_offenses()
   for offense in offenses:
       if offense['id'] not in sent_offenses_cache:
           teams_message = create_offense_for_teams(offense)
           post_to_teams(teams_message)
           sent_offenses_cache.add(offense['id'])
   save_cache(sent_offenses_cache)
