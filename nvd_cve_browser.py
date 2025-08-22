"""
NVD CVE Browser – Streamlit App (Python 3) with NVD API delay compliance
"""
from __future__ import annotations
import os
import time
from datetime import date, datetime, timedelta
from typing import Dict, List, Tuple
import pandas as pd
import requests
from dateutil import tz
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import streamlit as st

# from google.cloud import secretmanager
# client = secretmanager.SecretManagerServiceClient()
# name = f"projects/refreshing-cat-447519-s2/secrets/nvd-api-key/versions/latest"
# api_key = client.access_secret_version(request={"name": name}).payload.data.decode("UTF-8")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 2000

def make_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1.2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def to_iso_utc(d: date, end_of_day: bool = False) -> str:
    if isinstance(d, datetime):
        dt = d
    else:
        if end_of_day:
            dt = datetime(d.year, d.month, d.day, 23, 59, 59, 999000)
        else:
            dt = datetime(d.year, d.month, d.day, 0, 0, 0, 0)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def pick_severity(metrics: Dict) -> Tuple[str | None, float | None]:
    try:
        if metrics is None:
            return None, None
        v31 = metrics.get("cvssMetricV31")
        if v31 and len(v31) > 0:
            data = v31[0].get("cvssData", {})
            return data.get("baseSeverity"), data.get("baseScore")
        v30 = metrics.get("cvssMetricV30")
        if v30 and len(v30) > 0:
            data = v30[0].get("cvssData", {})
            return data.get("baseSeverity"), data.get("baseScore")
        v2 = metrics.get("cvssMetricV2")
        if v2 and len(v2) > 0:
            score = v2[0].get("cvssData", {}).get("baseScore")
            if score is None:
                return None, None
            if score >= 9.0:
                sev = "CRITICAL"
            elif score >= 7.0:
                sev = "HIGH"
            elif score >= 4.0:
                sev = "MEDIUM"
            else:
                sev = "LOW"
            return sev, score
    except Exception:
        return None, None
    return None, None

def parse_vulns(payload: Dict) -> Tuple[pd.DataFrame, int]:
    vulns = payload.get("vulnerabilities", [])
    rows: List[Dict] = []
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        published = cve.get("published")
        last_modified = cve.get("lastModified")
        descriptions = cve.get("descriptions", [])
        desc_en = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
        metrics = cve.get("metrics", {})
        sev, score = pick_severity(metrics)
        rows.append(
            {
                "cve_id": cve_id,
                "published": published,
                "last_modified": last_modified,
                "severity": sev,
                "score": score,
                "description": desc_en,
            }
        )
    df = pd.DataFrame(rows)
    total = payload.get("totalResults", len(rows))
    return df, total

def fetch_cves(
    api_key: str | None,
    keyword: str | None,
    start_date: date | None,
    end_date: date | None,
    severities: List[str],
    start_index: int,
    results_per_page: int,
) -> Tuple[pd.DataFrame, int, Dict]:
    params: Dict[str, str | int] = {
        "startIndex": max(0, int(start_index)),
        "resultsPerPage": min(MAX_PAGE_SIZE, max(1, int(results_per_page))),
    }
    if keyword:
        params["keywordSearch"] = keyword.strip()
    if start_date:
        params["pubStartDate"] = to_iso_utc(start_date, end_of_day=False)
    if end_date:
        params["pubEndDate"] = to_iso_utc(end_date, end_of_day=True)
    # option 2 - partial success
    # if severities:
    #     # NVD API expects multiple severities to be passed as repeated parameters, not always comma-separated.
    #     # We'll send them as separate query params for broader compatibility.
    #     for idx, sev in enumerate(sorted(set(severities))):
    #         params[f"cvssV3Severity"] = sev if len(severities) == 1 else None
    #     if len(severities) > 1:
    #         # Build query string manually to ensure multiple cvssV3Severity params
    #         # e.g., ...&cvssV3Severity=CRITICAL&cvssV3Severity=HIGH
    #         severity_params = [("cvssV3Severity", sev) for sev in sorted(set(severities))]
    #     else:
    #         severity_params = []
    # else:
    #     severity_params = []
    # option 1 - partial success
    if severities:
        # Join multiple severities into a comma-separated list, per NVD API spec
        params["cvssV3Severity"] = ",".join(sorted(set(severities)))
        # print("Using severities:", params["cvssV3Severity"])  # Debug check
        # params["cvssV3Severity"] = ",".join(sorted(set(severities)))

    headers = {"User-Agent": "NVD-CVE-Browser/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    else:
        api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        st.error("NVD API key not set. Please configure it in App Engine's env_variables.")
        st.stop()


    # Comply with NVD's 6-second delay guideline
    st.info("Sleeping 6 seconds before making the NVD API request (per API guidelines)...")
    time.sleep(6)

    session = make_session()
    # option 2 - partial success
    # if severity_params:
    #     resp = session.get(NVD_API_URL, params=[*params.items(), *severity_params], headers=headers, timeout=30)
    # else:
    #     resp = session.get(NVD_API_URL, params=params, headers=headers, timeout=30)
    # option 1 - partial success
    resp = session.get(NVD_API_URL, params=params, headers=headers, timeout=30)

    meta = {
        "request_url": resp.url,
        "status_code": resp.status_code,
        "ratelimit_limit": resp.headers.get("X-RateLimit-Limit"),
        "ratelimit_remaining": resp.headers.get("X-RateLimit-Remaining"),
        "ratelimit_reset": resp.headers.get("X-RateLimit-Reset"),
    }
# added 404 handling - improved response
    if resp.status_code == 200:
        payload = resp.json()
        df, total = parse_vulns(payload)
        return df, total, meta
    elif resp.status_code == 404:
        return pd.DataFrame(), 0, meta  # return empty set if no results found
    else:
        try:
            err = resp.json()
        except Exception:
            err = {"message": resp.text[:500]}
        raise RuntimeError(f"NVD API error {resp.status_code}: {err}")

# Streamlit UI - G's 3rd attempt
st.set_page_config(page_title="NVD CVE Browser", page_icon="🛡️", layout="wide")

st.title("🛡️ Example NVD CVE Browser - caution: unencrypted communication - use at your own risk.")
st.caption("Search, filter, and export CVE data from the National Vulnerability Database (API v2).")

with st.sidebar:
    st.header("Search & Filters")
    default_api_key = os.getenv("NVD_API_KEY")
    # Disable API key input and potential reveal of value stored in secret keystore
    # api_key = st.text_input("NVD API Key", value=default_api_key if default_api_key else "", type="password")
    api_key = value=default_api_key
    keyword = st.text_input("Keyword", value="", placeholder="e.g., openssl, cisco asa")
    today = date.today()
    last_30 = today - timedelta(days=30)
    col_a, col_b = st.columns(2)
    with col_a:
        start_date = st.date_input("Published from", value=last_30)
    with col_b:
        end_date = st.date_input("Published to", value=today)
    severities = st.multiselect("Severity (CVSS v3) - select one", options=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL"])
    st.subheader("Pagination")
    page_size = st.number_input("Results per page", min_value=1, max_value=MAX_PAGE_SIZE, value=DEFAULT_PAGE_SIZE, step=1)
    if "start_index" not in st.session_state:
        st.session_state.start_index = 0
    reset = st.button("🔄 New Search (reset page)")
    if reset:
        st.session_state.start_index = 0
    fetch_btn = st.button("🔍 Fetch CVEs", use_container_width=True)

error_box = st.empty()
results_df: pd.DataFrame | None = None
results_total: int | None = None
resp_meta: Dict | None = None

if fetch_btn:
    try:
        df, total, meta = fetch_cves(api_key=api_key.strip() or None, keyword=keyword or None, start_date=start_date, end_date=end_date, severities=severities, start_index=st.session_state.start_index, results_per_page=int(page_size))
        results_df, results_total, resp_meta = df, total, meta
    except Exception as exc:
        error_box.error(f"❌ {exc}")

if results_df is not None:
    st.dataframe(results_df, use_container_width=True, hide_index=True)
    csv_bytes = results_df.to_csv(index=False).encode("utf-8")
    json_bytes = results_df.to_json(orient="records", indent=2).encode("utf-8")
    st.download_button("⬇️ Download CSV", data=csv_bytes, file_name="nvd_cve_results.csv", mime="text/csv")
    st.download_button("⬇️ Download JSON", data=json_bytes, file_name="nvd_cve_results.json", mime="application/json")
else:
    st.info("Use the sidebar to set filters, then click **Fetch CVEs**.")

