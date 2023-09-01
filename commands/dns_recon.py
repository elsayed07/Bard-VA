import json
import re
from typing import Any, Optional
import dns.resolver
import requests
from rich.progress import track

model_engine = "text-davinci-003"


'''def extract_data(json_string: str) -> Any:
    # Define the regular expression patterns for individual values
    A_pattern = r'"A": \["(.*?)"\]'
    AAA_pattern = r'"AAA: \["(.*?)"\]'
    NS_pattern = r'"NS": \["(.*?)"\]'
    MX_pattern = r'"MX": \["(.*?)"\]'
    PTR_pattern = r'"PTR": \["(.*?)"\]'
    SOA_pattern = r'"SOA": \["(.*?)"\]'
    TXT_pattern = r'"TXT": \["(.*?)"\]'

    # Initialize variables for extracted data
    A = None
    AAA = None
    NS = None
    MX = None
    PTR = None
    SOA = None
    TXT = None

    # Extract individual values using patterns
    match = re.search(A_pattern, json_string)
    if match:
        A = match.group(1)

    match = re.search(AAA_pattern, json_string)
    if match:
        AAA = match.group(1)

    match = re.search(NS_pattern, json_string)
    if match:
        NS = match.group(1)

    match = re.search(MX_pattern, json_string)
    if match:
        MX = match.group(1)

    match = re.search(PTR_pattern, json_string)
    if match:
        PTR = match.group(1)

    match = re.search(SOA_pattern, json_string)
    if match:
        SOA = match.group(1)

    match = re.search(TXT_pattern, json_string)
    if match:
        TXT = match.group(1)

    # Create a dictionary to store the extracted data
    data = {
        "A": A,
        "AAA": AAA,
        "NS": NS,
        "MX": MX,
        "PTR": PTR,
        "SOA": SOA,
        "TXT": TXT
    }

    # Convert the dictionary to JSON format
    json_output = json.dumps(data)

    return json_output'''
    

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



'''def BardAI(key: str, data: Any) -> str:
    prompt = f"""
        Do a DNS analysis on the provided DNS scan information
        The DNS output must return in a JSON format accorging to the provided
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
        DNS Data to be analyzed: {data}
        """

    url = "https://generativelanguage.googleapis.com/v1beta2/models/text-bison-001:generateText?key=" + key

    headers = {
        "Content-Type": "application/json"
    }

    data = {
        "prompt": {
            "text": prompt
        }
    }

    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 200:
        generated_text = response.json()
        data = extract_data(str(generated_text))
        print(data)
        return extract_data(str(generated_text))
    else:
        print("Error: Unable to generate text. Status Code:", response.status_code)
        return "None"'''
        
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



'''def chat_with_api(api_url, user_message, user_instruction, model_name, file_name=None):
    # Prepare the request data in JSON format
    data = {
        'user_message': user_message,
        'model_name': model_name,
        'file_name': file_name,
        'user_instruction': user_instruction
    }

    # Send the POST request to the API
    response = requests.post(api_url, json=data)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        return response.json()['bot_response']
    else:
        # If there was an error, print the error message
        print(f"Error: {response.status_code} - {response.text}")
        return None'''
        

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