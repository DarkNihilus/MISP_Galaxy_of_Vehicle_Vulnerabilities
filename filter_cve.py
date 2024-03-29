import os
import json
import re
import uuid

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
    if not os.path.exists('relevant_cves'):
        os.makedirs('relevant_cves')
    for year in range(1999, 2025):
        filename = f"relevant_cves/{year}_relevant_vehicle_cves.json"
        if os.path.exists(filename):
            os.remove(filename)
            print(f"The file {filename} has been successfully deleted.")
        else:
            print(f"The file {filename} doesn't exit.")



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

    # Process each year directory
    for year_dir in year_dirs:
        year = os.path.basename(year_dir)
        relevant_cves = process_year_directory(year_dir)

        # Write filtered CVE data to a new JSON file for each year
        with open(f'relevant_cves/{year}_relevant_vehicle_cves.json', 'w') as f:
            json.dump(relevant_cves, f, indent=4)
            print(f'Relevant CVE data for {year} written to relevant_cves/{year}_relevant_vehicle_cves.json')

        # Count the number of CVEs and print the count
        num_cves = len(relevant_cves)
        print(f"Total number of CVEs in {year}: {num_cves}")

if __name__ == "__main__":
    main()
