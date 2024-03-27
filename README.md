# MISP_Galaxy_of_Vehicle_Vulnerabilities

***Authors***: Alecis Blanchet & Florent Vaidie

***Teachers***: Alexandre Dulaunoy [@adulau](https://github.com/adulau) & Christian Studer [@chris3rd](https://github.com/chrisr3d)

## Context
Vehicle's security has relied on them being isolated systems for a long time, leading to little or no internal security on the Control Area Network (CAN) bus used for internal communication. However today's vehicles not only rely more than ever on electronics, especially for safety features, but are more and more connected (Radio, Bluetooth, WiFi...) making for great surface of attack and potential impact.
This project aims to provide an easy way to find Common Vulnerabilities and Exposures (CVE) relating to vehicle security by integrating them as a MISP Galaxy.

## Methodology
- Collect CVE data using this [CVE List](https://github.com/CVEProject/cvelistV5/)
- Filter the data to focus on vehicle related vulnerabilities
- Structure the filtered data into a MISP cluster for integration

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


### Step 3: Creation of cluster and galaxy
Finally we use `create_galaxy.py` to create the cluster of CVE and the galaxy related



```sh
python create_galaxy.py
```


## Conclusion
(https://training6.misp-community.org/)
