import os
import re
import json
import uuid

def update_cluster_with_cves():
    cluster = {
        "authors": ["Alexis Blanchet", "Florent Vaidie"],
        "category": "vulnerabilities",
        "description": "CVEs relating to vulnerabilities in vehicles",
        "name": "Vehicle Vulnerabilities",
        "source": "https://github.com/CVEProject/cvelistV5",
        "type": "vulnerabilities",
        "uuid": str(uuid.uuid4()),
        "values": []
    }

    if not os.path.exists('clusters'):
        os.makedirs('clusters')
    filename = f"clusters/vehicle-vulnerabilities.json"
    if os.path.exists(filename):
        os.remove(filename)
        print(f"The file {filename} has been successfully deleted.")
    else:
        print(f"The file {filename} doesn't exit.")

    for filename in os.listdir('relevant_cves'):
        if filename.endswith('.json'):
            with open(os.path.join('relevant_cves', filename), 'r') as f:
                relevant_cves = json.load(f)
                # Format each CVE before adding it to the cluster
                formatted_cves = [format_cve(cve) for cve in relevant_cves]
                cluster['values'].extend(formatted_cves)

    with open('clusters/vehicle-vulnerabilities.json', 'w') as f:
        json.dump(cluster, f, indent=4)

    return cluster


def format_cve(cve):
    uuid_cve = str(uuid.uuid4())

    # Looking for a field 'uuid' already in the CVE
    for key, value in cve.items():
        if isinstance(value, str) and re.match(r"^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", value):
            uuid_cve = value
            break

    description = ''
    if 'containers' in cve and 'cna' in cve['containers'] and 'descriptions' in cve['containers']['cna']:
        description = cve['containers']['cna']['descriptions'][0].get('value', '')

    cve_id = ''
    if 'containers' in cve and 'cna' in cve['containers'] and 'x_legacyV4Record' in cve['containers']['cna']:
        cve_id = cve['containers']['cna']['x_legacyV4Record']['CVE_data_meta'].get('ID', '')

    formatted_cve = {
        "description": description,
        "meta": cve.get('cveMetadata', {}),
        "uuid": uuid_cve,
        "value": cve_id  
    }
    return formatted_cve



def create_galaxy(cluster):
    galaxy = {
        "description": "Vehicule Vulnerabilities galaxy based on open sources CVE.",
        "name": cluster.get('name', ''),
        "namespace": "misp",
        "type": cluster.get('type', ''),
        "uuid": str(uuid.uuid4()),
        "version": 3
    }

    if not os.path.exists('galaxies'):
        os.makedirs('galaxies')
    filename = f"galaxies/vehicle-vulnerabilities-galaxy.json"
    if os.path.exists(filename):
        os.remove(filename)
        print(f"The file {filename} has been successfully deleted.")
    else:
        print(f"The file {filename} doesn't exit.")

    with open('galaxies/vehicle-vulnerabilities-galaxy.json', 'w') as f:
        json.dump(galaxy, f, indent=4)
    return galaxy


def main():
    cluster = update_cluster_with_cves()
    num_cves = len(cluster.get('values', []))
    # Print the content of the cluster
    print(f"Cluster information:")
    print(f"Name: {cluster.get('name', '')}")
    print(f"Description: {cluster.get('description', '')}")
    print(f"Type: {cluster.get('type', '')}")
    print(f"Number of CVEs: {num_cves}")

    galaxy = create_galaxy(cluster)
    # Print the content of the galaxy
    print("Galaxy content:")
    print(json.dumps(galaxy, indent=4))

if __name__ == "__main__":
    main()