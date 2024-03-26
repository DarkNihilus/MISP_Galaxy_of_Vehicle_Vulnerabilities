import os
import json
from pymisp import PyMISP, MISPEvent, MISPObject

# MISP API Configuration
misp_url = 'https://training6.misp-community.org/'
misp_key = '9jvk2ERDndVTvaIBXi8HD2OJJsLSxsRYznSZEpNj'
misp_verifycert = True  # Vous pouvez définir cela sur True si votre instance MISP utilise un certificat SSL valide

# Connection to the MISP instance
misp = PyMISP(misp_url, misp_key, misp_verifycert)

directory = os.getcwd()

def create_misp_galaxy(filepath):
    for year in range(1999, 2025):
        filename = f"{year}_relevant_vehicle_cves.json"
        filepath = os.path.join(directory, filename)
        if os.path.exists(filepath):
            with open(filepath, 'r') as file:
                cve_data = json.load(file)
                for cve in cve_data:
                    # Extract information from CVE
                    cve_id = cve.get('cveMetadata', {}).get('cveId')
                    description = cve.get('containers', {}).get('cna', {}).get('descriptions', [])[0].get('value', '')

                    # Creation of a new MISP object
                    misp_object = MISPObject('cve')
                    misp_object.add_attribute('CVE_ID', cve_id, type='text')
                    misp_object.add_attribute('Description', description, type='text')

                    # Add the CVSS Score if it exist
                    cvss_score = cve.get('containers', {}).get('cna', {}).get('metrics', [{}])[0].get('cvssV3_1', {}).get('baseScore')
                    if cvss_score:
                        misp_object.add_attribute('CVSS_Score', cvss_score, type='float')

                    # Send the new object to a new MISP Event
                    misp_event = MISPEvent()
                    misp_event.info = f'MISP Event for {cve_id}'
                    misp_event.add_object(misp_object)

                    # Send the Event
                    response = misp.add_event(misp_event)

                    # Check the answer
                    if response and response.get('Event'):
                        print(f"Event for CVE {cve_id} created successfully. Event ID: {response['Event']['id']}")
                    else:
                        print(f"Failed to create event for CVE {cve_id}.")
        else:
            print(f"File {filename} does not exist.")


def remove_misp_event_files(directory):
    for filename in os.listdir(directory):
        if filename.endswith('_misp_event.json'):
            os.remove(os.path.join(directory, filename))
            print(f"File {filename} removed.")


# To remove the file if they already exist
remove_misp_event_files(directory)

create_misp_galaxy(directory)
