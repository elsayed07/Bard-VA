import json
import re
from typing import Any, Optional
import dns.resolver
import requests
from rich.progress import track

model_engine = "text-davinci-003"    

def extract_data(json_string: str) -> str:
    record_patterns = {
        "A": r'"A": \["(.*?)"\]',
        "AAA": r'"AAA: \["(.*?)"\]',
        "NS": r'"NS": \["(.*?)"\]',
        "MX": r'"MX": \["(.*?)"\]',
        "PTR": r'"PTR": \["(.*?)"\]',
        "SOA": r'"SOA": \["(.*?)"\]',
        "TXT": r'"TXT": \["(.*?)"\]'
    }

    data = {}

    for key, pattern in record_patterns.items():
        match = re.search(pattern, json_string)
        if match:
            data[key] = match.group(1)

    json_output = json.dumps(data)
    return json_output

        
def generate_bard_text(key: str, prompt: str) -> str:
    url = "https://generativelanguage.googleapis.com/v1beta2/models/text-bison-001:generateText?key=" + key

    headers = {"Content-Type": "application/json"}
    data = {"prompt": {"text": prompt}}

    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 200:
        generated_text = response.json()
        return extract_data(str(generated_text))
    else:
        print("Error: Unable to generate text. Status Code:", response.status_code)
        return "None"
    

def BardAI(api_key: str, dns_data: Any) -> str:
    prompt = f"""
        Do a DNS analysis on the provided DNS scan information
        The DNS output must return in a JSON format according to the provided
        output format. The data must be accurate in regards towards a pentest report.
        The data must follow the following rules:
        1) The DNS scans must be done from a pentester point of view
        2) The final output must be minimal according to the format given
        3) The final output must be kept to a minimal

        The output format:
        {{
            "A": [""],
            "AAA": [""],
            "NS": [""],
            "MX": [""],
            "PTR": [""],
            "SOA": [""],
            "TXT": [""]
        }}
        DNS Data to be analyzed: {dns_data}
        """

    return generate_bard_text(api_key, prompt)

        
def chat_with_api(api_url, user_message, user_instruction, model_name, file_name=None):
    data = {
        'user_message': user_message,
        'model_name': model_name,
        'file_name': file_name,
        'user_instruction': user_instruction
    }

    response = requests.post(api_url, json=data)

    if response.status_code == 200:
        return response.json().get('bot_response')
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None


def dnsr(target: str, akey: Optional[str], bkey: Optional[str], AI: str) -> Any:
    if target is not None:
        pass
    else:
        raise ValueError("InvalidTarget: Target Not Provided")
    analyze = ''
    # The DNS Records to be enumeratee
    record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']
    for records in track(record_types):
        try:
            answer = dns.resolver.resolve(target, records)
            for server in answer:
                st = server.to_text()
                analyze += "\n"
                analyze += records
                analyze += " : "
                analyze += st
        except dns.resolver.NoAnswer:
            print('No record Found')
            pass
        except dns.resolver.NXDOMAIN:
            print('NXDOMAIN record NOT Found')
            pass
        except dns.resolver.LifetimeTimeout:
            print("Timmed out check your internet")
            pass
        except KeyboardInterrupt:
            print("Bye")
            quit()
    response = ""
    match AI:
        case 'bard':
            try:
                if akey is not None:
                    pass
                else:
                    raise ValueError("KeyNotFound: Key Not Provided")
                response = BardAI(bkey, analyze)
            except KeyboardInterrupt:
                print("Bye")
                quit()

    return str(response)