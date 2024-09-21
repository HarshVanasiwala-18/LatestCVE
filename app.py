from flask import Flask, render_template, request
from flask_paginate import Pagination, get_page_parameter
import requests
from datetime import datetime

app = Flask(__name__)

# Define the list of URLs with their corresponding origin names and source URLs
urls = [
    {
        "url": "https://cve.circl.lu/api/last",
        "origin": "CIRCL",
        "source_url": "https://cve.circl.lu/api/last"
    },
    {
        "url": "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json",
        "origin": "GitHub",
        "source_url": "https://github.com/CVEProject/cvelistV5"
    }
]

# Set headers to mimic a browser request with additional headers
headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/112.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "Referer": "https://www.google.com/",
    "Cache-Control": "no-cache"
}

def fetch_url_content(url_info, headers):
    url = url_info.get("url")
    origin = url_info.get("origin")
    source_url = url_info.get("source_url")
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        try:
            content = response.json()
        except ValueError:
            content = response.text
        
        return {
            "origin": origin,
            "source_url": source_url,
            "url": url,
            "content": content
        }
    except requests.exceptions.RequestException as e:
        return {
            "origin": origin,
            "source_url": source_url,
            "url": url,
            "error": str(e)
        }

def parse_circl_data(content, origin):
    parsed = []
    for entry in content:
        cve_id = entry.get('id')
        date = entry.get('Published')
        references = entry.get('references', [])
        refs = references if isinstance(references, list) else [references]
        
        if cve_id and date:
            parsed.append({
                "CVE_ID": cve_id,
                "Date": format_date(date),
                "RawDate": date,  # Keep raw date for comparison
                "References": refs,
                "Origin": [origin]
            })
    return parsed

def parse_github_data(content, origin):
    parsed = []
    
    if not isinstance(content, list):
        return parsed
    
    for log_entry in content:
        for change_type in ['new', 'updated']:
            cve_entries = log_entry.get(change_type, [])
            for cve_item in cve_entries:
                cve_id = cve_item.get('cveId')
                date = cve_item.get('dateUpdated')
                references = []
                cve_org_link = cve_item.get('cveOrgLink')
                github_link = cve_item.get('githubLink')
                
                if cve_org_link:
                    references.append(cve_org_link)
                if github_link:
                    references.append(github_link)
                
                if cve_id and date:
                    parsed.append({
                        "CVE_ID": cve_id,
                        "Date": format_date(date),
                        "RawDate": date,  # Keep raw date for comparison
                        "References": references,
                        "Origin": [origin]
                    })
    
    return parsed

def format_date(date_str):
    # Try parsing the GitHub date format (ISO 8601 with 'Z')
    try:
        dt = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%fZ')
        # Convert to the desired format
        return dt.strftime('%B %d, %Y %I:%M %p')
    except ValueError:
        pass

    # Try parsing the CIRCL format (if different)
    try:
        dt = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S')
        return dt.strftime('%B %d, %Y %I:%M %p')
    except ValueError:
        return date_str

def filter_today_cves(cve_entries):
    today = datetime.now().strftime('%Y-%m-%d')
    filtered = []
    
    for cve in cve_entries:
        cve_date = cve.get("RawDate", "")
        if today in cve_date:
            filtered.append(cve)
    
    return filtered

def deduplicate_cve_entries(cve_entries):
    deduplicated = {}
    for entry in cve_entries:
        cve_id = entry.get("CVE_ID")
        if not cve_id:
            continue
        
        if cve_id not in deduplicated:
            deduplicated[cve_id] = {
                "CVE_ID": cve_id,
                "Date": entry.get("Date"),
                "References": set(entry.get("References", [])),
                "Origin": set(entry.get("Origin", [])),
                "RawDate": entry.get("RawDate")  # Include RawDate for filtering
            }
        else:
            deduplicated[cve_id]["References"].update(entry.get("References", []))
            deduplicated[cve_id]["Origin"].update(entry.get("Origin", []))
    
    final_deduplicated = []
    for cve in deduplicated.values():
        final_deduplicated.append({
            "CVE_ID": cve["CVE_ID"],
            "Date": cve["Date"],
            "References": list(cve["References"]),
            "Origin": list(cve["Origin"]),
            "RawDate": cve["RawDate"]
        })
    
    return final_deduplicated

def extract_cve_data():
    collected_data = []
    
    for url_info in urls:
        data = fetch_url_content(url_info, headers)
        collected_data.append(data)
    
    all_cves = []
    for data in collected_data:
        if 'error' in data:
            continue
        
        origin = data['origin']
        content = data['content']
        
        if origin == "CIRCL":
            if isinstance(content, list):
                cves = parse_circl_data(content, origin)
                all_cves.extend(cves)
        
        elif origin == "GitHub":
            if isinstance(content, list):
                cves = parse_github_data(content, origin)
                all_cves.extend(cves)
    
    deduplicated_cves = deduplicate_cve_entries(all_cves)
    
    # Filter CVEs to only show those published today
    today_cves = filter_today_cves(deduplicated_cves)
    
    return today_cves

@app.route('/')
def home():
    # Fetch data
    cve_entries = extract_cve_data()
    
    # Get the current search query
    search_query = request.args.get('search', '')
    if search_query:
        cve_entries = [entry for entry in cve_entries if search_query.lower() in entry['CVE_ID'].lower()]

    # Implement pagination
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 10
    paginated_cves = cve_entries[(page - 1) * per_page: page * per_page]
    
    pagination = Pagination(page=page, total=len(cve_entries), per_page=per_page, search=False, record_name='CVEs')

    return render_template('index.html', cve_entries=paginated_cves, pagination=pagination, search_query=search_query)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
