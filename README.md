# NVD_Browser
The challenge is to create a Python3 based application that interacts with the NVD (National Vulnerability Database) API to fetch, display, and manage CVE (Common Vulnerabilities and Exposures) data.

Details about this API can be found here: https://nvd.nist.gov/developers/start-here.

The GCP App engine config is included, if you want to run this on GCP.
For AWS AppRunner, a `Dockerfile` was created and the container uploaded to ECR.

The requirements include:
- An API key that can be generated from https://nvd.nist.gov/developers/request-an-api-key
- Python v.3.12 or greater
- Install any modules needed as described in 'requirements.txt'
- Outbound connectivity to https://services.nvd.nist.gov/rest/json/cves/2.0

To run locally, clone this repository to a local directory and change to that directory.
Then in the terminal, run `streamlit run nvd_cve_browser.py`

The service will open your default browswer to a localhost url similar to “http://localhost:8501/“ .  

