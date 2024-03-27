import os
import json
import re

def filter_cves(cve_data):
    vehicle_keywords = ['car', 'can bus', 'automotive', 'vehicle']
    # Add other keyword to exclude some CVE
    exclusion_keywords = ['router', 'server', 'http', 'online', 'booking', 'simulator', 'android', 'plugin', 'customize login image', 'call detail', 'car wallpapers', 'car insurance', 'car portal', 'cars portal', 'car site', 'car dealer', 'car repair', 'car seller', 'car classifieds', 'rental', 'x2crm']

    relevant_cves = []

    for cve in cve_data:
        descriptions = cve.get('containers', {}).get('cna', {}).get('descriptions', [])
        affected = cve.get('containers', {}).get('cna', {}).get('affected', [{}])
        product_text = ' '.join([p.get('product', '').lower() for p in affected])
        state = cve.get('cveMetadata', {}).get('state', '').lower()

        if state == 'rejected':
            continue

        description_text = ' '.join([d.get('value', '').lower() for d in descriptions])

        # Check the presence of keyword and the absence of exclusion keyword
        relevant = False
        for keyword in vehicle_keywords:
            if f' {keyword} ' in description_text:  
                relevant = True
                break

        if relevant:
            for exclude in exclusion_keywords:
                if f' {exclude} ' in description_text or f' {exclude} ' in product_text: 
                    relevant = False
                    break

        if relevant:
            relevant_cves.append(cve)

    return relevant_cves


def delete_relevant_cve_files():
    for year in range(1999, 2025):
        filename = f"{year}_relevant_vehicle_cves.json"
        if os.path.exists(filename):
            os.remove(filename)
            print(f"Le fichier {filename} a été supprimé avec succès.")
        else:
            print(f"Le fichier {filename} n'existe pas.")


def process_year_directory(year_dir):
    relevant_cves = []

    for root, dirs, files in os.walk(year_dir):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        cve_data = json.load(f)
                        relevant_cves.extend(filter_cves([cve_data])) 
                except json.JSONDecodeError:
                    print(f"Error reading JSON file: {file_path}")

    return relevant_cves



def main():
    cvelist_dir = 'cvelistV5/cves'
    delete_relevant_cve_files()
    # List all year directories
    year_dirs = [os.path.join(cvelist_dir, d) for d in os.listdir(cvelist_dir) if os.path.isdir(os.path.join(cvelist_dir, d))]
    # Create cluster
    cluster = {"authors":["Alexis Blanchet", "Florent Vaidie"], "category": "vulnerabilities", "description": "CVEs relating to vulnerabilities in vehicles", "name":"Vehicle Vulnerabilities", "source": "https://github.com/CVEProject/cvelistV5", "type": "vulnerabilities", "uuid": "5b9461d6-6e42-4623-91b2-1f6ed4d66296"}

    # Process each year directory
    for year_dir in year_dirs:
        year = os.path.basename(year_dir)
        relevant_cves = process_year_directory(year_dir)

        # Write filtered CVE data to a new JSON file for each year
        with open(f'{year}_relevant_vehicle_cves.json', 'w') as f:
            json.dump(relevant_cves, f, indent=4)
            print(f'Relevant CVE data for {year} written to {year}_relevant_vehicle_cves.json')

        # Count the number of CVEs and print the count
        num_cves = len(relevant_cves)
        print(f"Total number of CVEs in {year}: {num_cves}")

        # Add CVE data to the cluster
        cluster.update({"values":relevant_cves})
    cluster.update({"version": 1})
    with open("clusters/vehicle-vulnerabilities.json", "w") as outfile:
    json.dump(cluster, outfile,indent = 4)

if __name__ == "__main__":
    main()
