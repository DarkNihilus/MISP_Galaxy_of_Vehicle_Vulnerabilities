import os
import argparse
import requests
from git import Repo

# Parse command line arguments
parser = argparse.ArgumentParser(description='Download JSON files from MITRE CVE.')
parser.add_argument('-d', '--directory', default='cve_json_files', help='Directory to save downloaded files.')
args = parser.parse_args()

def download_file(url, directory):
    try:
        # Extract filename from URL
        filename = url.split('/')[-1]
        local_path = os.path.join(directory, filename)

        # Check if file already exists
        if os.path.exists(local_path):
            print(f"File {filename} already exists, skipping.")
            return

        # Attempt to download the file
        response = requests.get(url)
        if response.status_code == 200:
            with open(local_path, 'wb') as f:
                f.write(response.content)
            print(f"Downloaded {filename}")
        else:
            print(f"Failed to download {filename}: HTTP {response.status_code}")
    except Exception as e:
        print(f"Error downloading {url}: {e}")

def download_xml_cve(url, directory):
    # Ensure directory exists
    os.makedirs(directory, exist_ok=True)

    # Download JSON file
    download_file(url, directory)

def download_json_cve(git_url, local_path):
    if not os.path.exists(local_path):
        print("Cloning CVEList repository...")
        Repo.clone_from(git_url, local_path)
        print("Repository cloned successfully.")
    else:
        print("CVEList repository already exists. Skipping cloning.")

def main():
    # List of JSON URLs to download
    json_urls = [
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2019.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2018.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2017.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2016.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2015.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2014.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2013.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2012.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2011.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2010.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2009.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2008.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2007.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2006.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2005.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2004.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2003.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2002.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2001.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2000.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf-year-1999.xml",
        "https://cve.mitre.org/data/downloads/allitems-cvrf.xml"
    ]

    # Download files one by one
    for url in json_urls:
        download_xml_cve(url, args.directory)

    print("Finished downloading JSON files.")

    # URL du dépôt Git du projet CVEList
    git_url = "https://github.com/CVEProject/cvelistV5.git"
    
    # Répertoire local pour cloner le dépôt
    local_path = "cvelistV5"
    
    # Télécharger le dépôt Git
    download_json_cve(git_url, local_path)

if __name__ == "__main__":
    main()
