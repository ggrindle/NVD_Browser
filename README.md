# NVD_Browser
The challenge is to create a Python3 based application that interacts with the NVD (National Vulnerability Database) API to fetch, display, and manage CVE (Common Vulnerabilities and Exposures) data.

Details about this API can be found here: https://nvd.nist.gov/developers/start-here.

The GCP App engine config is included, if you want to run this on GCP.

This can be run locally.  The requirements include:
<ul>
<li>An API key that can be generated from https://nvd.nist.gov/developers/request-an-api-key</li>
<li>Python v.3.12 or greater</li>
<li>Install any modules needed as described in 'requirements.txt'</li>
<li>Outbound connectivity to https://services.nvd.nist.gov/rest/json/cves/2.0</li>
</ul>

To run this code, clone this repository to a local directory and change to that directory.
Then run <code>streamlit run nvd_cve_browser.py</code> in the terminal.

The service will open your default browswer to a localhost url similar to “http://localhost:8501/“ .  

