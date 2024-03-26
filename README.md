# MISP_Galaxy_of_Vehicle_Vulnerabilities

## Description
This project scrap json file from https://github.com/CVEProject/cvelistV5.git and create new json file for each year containing relevent CVE related to Vehicule vulnerability

## Requirements
- Python 3
- Requests library

You can use this command to install the requirement:

```sh
pip install -r requirements.txt
```

### Step 1: Download JSON File from git
First we download files of CVE from the official list of CVE of MITRE (https://github.com/CVEProject/cvelistV5.git) by using `download_cve.py`

```sh
python download_cve.py
```

### Step 2: Filter the result with keyword
Then we use `filter_cve.py` to filter the vulnerability wich are related to vehicule

```sh
python filter_cve.py
```


### Step 3: Integration into MISP
Finally we use `integration.py` to create the CVE into a instance of training MISP (https://training6.misp-community.org/)

```sh
python integration.py
```


## Conclusion
