import json
import re
from typing import Any, Optional
import nmap
import requests

nm = nmap.PortScanner()
model_engine = "text-davinci-003"

def extract_data(json_string: str) -> Any:
    critical_score_pattern = r'"critical score": \["(.*?)"\]'
    os_information_pattern = r'"os information": \["(.*?)"\]'
    open_ports_pattern = r'"open ports": \["(.*?)"\]'
    open_services_pattern = r'"open services": \["(.*?)"\]'
    vulnerable_service_pattern = r'"vulnerable service": \["(.*?)"\]'
    found_cve_pattern = r'"found cve": \["(.*?)"\]'
    notes_and_recommendations_pattern = r'"notes and recommendations": .*'
    #\["(.*?)"\]'

    critical_score = None
    os_information = None
    open_ports = None
    open_services = None
    vulnerable_service = None
    found_cve = None
    notes_and_recommendations = None

    match = re.search(critical_score_pattern, json_string)
    if match:
        critical_score = match.group(1)

    match = re.search(os_information_pattern, json_string)
    if match:
        os_information = match.group(1)

    match = re.search(open_ports_pattern, json_string)
    if match:
        open_ports = match.group(1)

    match = re.search(open_services_pattern, json_string)
    if match:
        open_services = match.group(1)

    match = re.search(vulnerable_service_pattern, json_string)
    if match:
        vulnerable_service = match.group(1)

    match = re.search(found_cve_pattern, json_string)
    if match:
        found_cve = match.group(1)
        
    match = re.search(notes_and_recommendations_pattern, json_string)
    if match:
        notes_and_recommendations = match.group(0)

    data = {
        "critical score": critical_score,
        "os information": os_information,
        "open ports": open_ports,
        "open services": open_services,
        "vulnerable service": vulnerable_service,
        "found cve": found_cve,
        "notes and recommendations": notes_and_recommendations
        
    }

    json_output = json.dumps(data)

    return json_output

# 
def BardAI(key: str, data: Any) -> str:
    prompt = f"""
        Perform an in-depth analysis of the NMAP scan data provided, 
        ensuring that the resulting NMAP output is formatted as JSON and 
        aligns with the requirements of a comprehensive penetration test report.
        Adhere to the following guidelines:
        1. Approach NMAP scans from a penetration tester's perspective.
        2. Maintain minimalism in the final output while adhering to the specified format.
        3. Thoroughly examine even the most minute data points.
        4. Perform a comprehensive analysis of the provided data,
        presenting a definitive response in accordance with the specified output format.
        In cases where data is absent or nothing found, indicate none.
        5. indicate your recommendations about the scan


        The output format:
        {{
            "critical score": [""],
            "os information": [""],
            "open ports": [""],
            "open services": [""],
            "vulnerable service": [""],
            "found cve": [""]
            "notes and recommendations":[""]
        }}

        NMAP Data to be analyzed: {data}
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
    '''# Extract and format the recommendations
    recommendations = data.get("notes and recommendations", [])
    formatted_recommendations = "\n".join(recommendations)

    # Print the formatted recommendations
    print("Recommendations:")
    print(formatted_recommendations)'''
    
    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 200:
        generated_text = response.json()
        return extract_data(str(generated_text))
    else:
        print("Error: Unable to generate text. Status Code:", response.status_code)
        return "None"


def chat_with_api(api_url, user_message, user_instruction, model_name, file_name=None):
    data = {
        'user_message': user_message,
        'model_name': model_name,
        'file_name': file_name,
        'user_instruction': user_instruction
    }

    # Send the POST request to the API
    response = requests.post(api_url, json=data)
    if response.status_code == 200:
        return response.json()['bot_response']
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None


def p_scanner(ip: Optional[str], profile: int, akey: Optional[str], bkey: Optional[str], AI: str) -> Any:
    profile_argument = ""
    # The port profiles or scan types user can choose
    if profile == 1:
        profile_argument = '-Pn -sV -T4 -O -F'
    elif profile == 2:
        profile_argument = '-Pn -T4 -A -v'
    elif profile == 3:
        profile_argument = '-Pn -sS -sU -T4 -A -v'
    elif profile == 4:
        profile_argument = '-Pn -p- -T4 -A -v'
    elif profile == 5:
        profile_argument = '-Pn -sS -sU -T4 -A -PE -PP  -PY -g 53 --script=vuln'
    else:
        raise ValueError(f"Invalid Argument: {profile}")
    
    nm.scan('{}'.format(ip), arguments='{}'.format(profile_argument))
    json_data = nm.analyse_nmap_xml_scan()
    analyze = json_data["scan"]
    if AI == 'bard':
        try:
            if bkey is not None:
                response = BardAI(bkey, analyze)
            else:
                raise ValueError("KeyNotFound: Key Not Provided")
        except KeyboardInterrupt:
            print("Bye")
            quit()
    else:
        response = None

    return response
    