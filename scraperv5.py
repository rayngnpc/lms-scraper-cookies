# scraper.py

# 1. ALL YOUR IMPORTS GO AT THE TOP
import requests
from bs4 import BeautifulSoup
import os
from urllib.parse import urljoin, urlparse
import time
import base64 # For VirusTotal URL ID
import json
import csv
from datetime import datetime # For CSV report date formatting
import yaml
import re # Make sure re is imported

def get_cookies_from_raw_paste(cookie_filepath="raw_cookies.txt"):
    """
    Reads cookies from a raw text file (direct paste from browser dev tools cookie list)
    where each line is 'name<separator>value'.
    Constructs the single cookie string for HTTP headers.
    """
    cookie_pairs = []
    print(f"Attempting to load cookies from: {cookie_filepath}")
    try:
        with open(cookie_filepath, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'): # Skip empty lines or comments
                    continue

                # Try to split by tab first, as it's common.
                # If not tab, try to split by the first sequence of one or more spaces.
                # This regex captures the first non-whitespace block (name) 
                # and everything after the first block of whitespace (value).
                match = re.match(r"([^\s]+)\s+(.*)", line)
                
                if match:
                    name = match.group(1).strip()
                    value = match.group(2).strip()

                    # Values copied from browser tools are often enclosed in double quotes.
                    # Remove them if they are true framing quotes.
                    # Be careful if the cookie value ITSELF is supposed to contain quotes.
                    if value.startswith('"') and value.endswith('"'):
                        # Check if it's the _pk_ref.4.e4ea style value which is a stringified JSON
                        # For that one, the outer quotes are part of the value from browser copy
                        # but the actual cookie value doesn't include them.
                        # This is heuristic and might need adjustment based on how your browser copies.
                        # The safest is always copying the raw HTTP Cookie header.
                        
                        # A simple heuristic: if the value, after stripping quotes, still looks like
                        # a plausible cookie value (e.g., not empty), then use the stripped version.
                        # This is tricky because `_pk_ref.4.e4ea`'s value *is* a string that contains quotes.
                        # The value from `_pk_ref.4.e4ea	"[\"\",\"\",1747170836,\"https://login.microsoftonline.com/\"]"`
                        # after stripping the outer quotes becomes: `["","",1747170836,"https://login.microsoftonline.com/"]`
                        # which is correct.
                        
                        temp_val = value[1:-1]
                        value = temp_val # Assume outer quotes are from copy-paste display

                    if name: 
                        cookie_pairs.append(f"{name}={value}")
                    else:
                        print(f"Warning: Empty cookie name on line {line_num} in '{cookie_filepath}': '{line}'")
                elif line: # Line couldn't be split into two parts by whitespace
                    # Could be a cookie with no value, just a name (e.g., "secure")
                    # Or an invalid line.
                    # If it doesn't contain '=', assume it's a name-only cookie.
                    if '=' not in line and line.isalnum(): # Simple check for name-only
                         cookie_pairs.append(f"{line.strip()}=") # name= (empty value)
                    else:
                        print(f"Warning: Could not parse cookie line {line_num} in '{cookie_filepath}' into name/value: '{line}'")

        if cookie_pairs:
            full_cookie_string = "; ".join(cookie_pairs)
            print(f"Successfully constructed cookie string from '{cookie_filepath}'.")
            #   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
            #   <<<<< THIS IS THE CRUCIAL DEBUG PRINT >>>>>
            #   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
            print(f"--- BEGIN CONSTRUCTED COOKIE HEADER ---")
            print(f"[{full_cookie_string}]")
            print(f"--- END CONSTRUCTED COOKIE HEADER ---")
            return full_cookie_string
        else:
            print(f"ERROR: No valid cookie pairs found or constructed from '{cookie_filepath}'.")
            return None

    except FileNotFoundError:
        print(f"ERROR: Cookie file '{cookie_filepath}' not found. Please create it and paste your cookies.")
        return None
    except Exception as e:
        print(f"ERROR: An unexpected error occurred while loading cookies from '{cookie_filepath}': {e}")
        return None

# --- Configuration (in your scraperdebug.py) ---
MY_LMS_COOKIE = get_cookies_from_raw_paste() 

if MY_LMS_COOKIE is None:
    print("CRITICAL: LMS Cookie could not be loaded or constructed. Please check 'raw_cookies.txt' and errors above.")
    exit("Exiting due to cookie loading failure.")

print(f"\n--- COOKIE STRING BEING USED BY REQUESTS ---")
print(f"[{MY_LMS_COOKIE}]")
print(f"--- END COOKIE STRING BEING USED ---\n")
# ... rest of your script's __main__ block ...

STARTING_COURSE_URL = "https://moodleprod.murdoch.edu.au/course/view.php?id=27406"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
DOWNLOAD_DIRECTORY = "./LMS/scrapperv4"

# --- DOMAIN CONFIGURATION ---
LMS_SPECIFIC_DOMAIN = "moodleprod.murdoch.edu.au"
UNIVERSITY_ROOT_DOMAIN = "murdoch.edu.au"

# --- CRAWLER CONFIGURATION ---
INTERNAL_COURSE_LINK_PATTERNS = [
    '/mod/resource/view.php',
    '/mod/page/view.php',
    '/mod/folder/view.php',
    '/mod/forum/view.php',
    '/mod/quiz/view.php',      # Main quiz page, not necessarily attempt links unless they contain content
    '/mod/assign/view.php',    # Main assignment page
    '/mod/lesson/view.php',
    '/mod/book/view.php',
    '/mod/url/view.php',       # Moodle URL resources (might redirect to external, or show an internal frame)
    '/mod/teammeeting/view.php', # Your example
    '/course/view.php',        # Main course page, section pages
    # Add other '/mod/.../view.php' patterns if you find more content types
] # <<< REVIEW AND CUSTOMIZE BASED ON YOUR MOODLE COURSE STRUCTURE

DOWNLOADABLE_EXTENSIONS = [
    '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx',
    '.zip', '.rar', '.7z', '.txt', '.csv', '.jpg', '.jpeg', '.png',
    '.gif', '.mp3', '.mp4', '.mov', '.avi', '.webm', '.odt', '.odp', '.ods'
]

# --- API CONFIGURATION ---
VIRUSTOTAL_API_KEY = "7094faaa85ff24ae769e48f5eae2ba1afbbdd74dd61ae582f613fb096b92e85f"
# --- End of Configuration ---


# 3. ALL YOUR HELPER FUNCTION DEFINITIONS GO HERE
def create_download_directory_structure():
    """Creates the main download directory and key subdirectories if they don't exist."""
    subdirs = ["html_pages", "downloaded_files_from_pages", "reports_and_summaries"]
    for subdir_name in subdirs:
        path = os.path.join(DOWNLOAD_DIRECTORY, subdir_name)
        if not os.path.exists(path):
            print(f"Creating directory: {path}")
            os.makedirs(path, exist_ok=True) # exist_ok=True is important
    # Ensure DOWNLOAD_DIRECTORY itself exists
    if not os.path.exists(DOWNLOAD_DIRECTORY):
         os.makedirs(DOWNLOAD_DIRECTORY, exist_ok=True)


def fetch_content(url_to_fetch, source_page_for_filename_context="UNKNOWN_SOURCE_PAGE"):
    """
    Fetches content from a URL. Returns a dictionary.
    """
    print(f"Attempting to fetch/download: {url_to_fetch}")
    
    if not MY_LMS_COOKIE or "YOUR_ACTUAL_COOKIE_STRING_HERE" in MY_LMS_COOKIE:
        print("ERROR: MY_LMS_COOKIE is not set. Please paste your cookie string.")
        return {'type': 'error', 'message': "Cookie not set", 'status_code': None, 'final_url': url_to_fetch}
    if not url_to_fetch.startswith("http"):
        print(f"ERROR: {url_to_fetch} is not a valid URL.")
        return {'type': 'error', 'message': "Invalid URL format", 'status_code': None, 'final_url': url_to_fetch}

    headers = {"User-Agent": USER_AGENT, "Cookie": MY_LMS_COOKIE}

    try:
        response = requests.get(url_to_fetch, headers=headers, timeout=30, stream=True, allow_redirects=True)
        final_url_after_redirects = response.url # Store the final URL after any redirects
        response.raise_for_status()

        content_type = response.headers.get('Content-Type', '').lower()
        content_disposition = response.headers.get('Content-Disposition', '') # Keep case for parsing filename

        is_direct_attachment = 'attachment' in content_disposition.lower()
        
        filename_from_header = None
        if 'filename=' in content_disposition: # Basic check
            # More robust parsing for filename*=UTF-8''name.ext
            import re
            match_utf8 = re.search(r"filename\*=UTF-8''([\w%.-]+)", content_disposition, re.IGNORECASE)
            match_simple = re.search(r'filename="?([^"]+)"?', content_disposition, re.IGNORECASE)
            if match_utf8:
                from urllib.parse import unquote_to_bytes
                filename_from_header = unquote_to_bytes(match_utf8.group(1)).decode('utf-8', 'surrogateescape')
            elif match_simple:
                filename_from_header = match_simple.group(1)
            
            if filename_from_header:
                 filename_from_header = filename_from_header.strip().strip('"').strip("'")


        is_likely_binary_type = any(ct_part in content_type for ct_part in [
            'application/pdf', 'application/msword', 'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'application/zip', 'application/x-tar', 'application/x-gzip', 'application/octet-stream', 
            'image/', 'video/', 'audio/'
        ])
        
        # Use final_url_after_redirects for path checks
        url_path_ends_with_download_ext = any(urlparse(final_url_after_redirects).path.lower().endswith(ext) for ext in DOWNLOADABLE_EXTENSIONS)

        is_file_to_download = is_direct_attachment or \
                              url_path_ends_with_download_ext or \
                              (is_likely_binary_type and not any(final_url_after_redirects.lower().endswith(page_ext) for page_ext in [".php", ".aspx", ".asp", ".html", ".htm", "/"]))


        if is_file_to_download:
            print(f"  Detected as direct file download. Final URL: {final_url_after_redirects}, CT: {content_type}, CD: {content_disposition}")
            
            filename = filename_from_header or os.path.basename(urlparse(final_url_after_redirects).path)
            if not filename or filename == "/": 
                path_segments_for_name = [s for s in urlparse(final_url_after_redirects).path.split('/') if s]
                if path_segments_for_name and not path_segments_for_name[-1].isdigit():
                    filename = path_segments_for_name[-1]
                else: 
                    filename = f"download_{urlparse(final_url_after_redirects).netloc}_{int(time.time())}"
            
            source_page_slug = urlparse(source_page_for_filename_context).path.replace('/', '_').replace('?','_').replace('=','_').strip('_') or "unknownpage"
            safe_filename = "".join(c for c in filename if c.isalnum() or c in ('.', '_', '-')).rstrip()
            if not safe_filename: safe_filename = f"file_{int(time.time())}"
            
            _, ext_check = os.path.splitext(safe_filename)
            if not ext_check: # Try to add extension if missing
                # Priority to extension in final URL path
                _, url_ext_final = os.path.splitext(urlparse(final_url_after_redirects).path)
                if url_ext_final and url_ext_final.lower() in DOWNLOADABLE_EXTENSIONS:
                    safe_filename += url_ext_final
                # Then try mime type
                elif 'pdf' in content_type: safe_filename += ".pdf"
                elif 'msword' in content_type or 'wordprocessingml' in content_type: safe_filename += ".docx"
                elif 'excel' in content_type or 'spreadsheetml' in content_type: safe_filename += ".xlsx"
                elif 'powerpoint' in content_type or 'presentationml' in content_type: safe_filename += ".pptx"
                elif 'zip' in content_type: safe_filename += ".zip"
                # Add more specific image/video types if desired, otherwise they get generic or no extension
            
            # Create a subfolder for files from this specific source page (or original URL if direct)
            # Use a slug from the *original* requested URL (url_to_fetch) for the subfolder name
            # to group files that were *intended* to be from that page, even if redirected.
            context_slug_for_folder = urlparse(url_to_fetch).path.replace('/', '_').replace('?','_').replace('=','_').strip('_') or "direct_downloads"
            file_download_subfolder = os.path.join(DOWNLOAD_DIRECTORY, "downloaded_files_from_pages", context_slug_for_folder)
            os.makedirs(file_download_subfolder, exist_ok=True)
            
            local_filepath = os.path.join(file_download_subfolder, safe_filename)
            
            # Avoid re-downloading if file already exists (simple check by path)
            if os.path.exists(local_filepath) and os.path.getsize(local_filepath) > 0 :
                 print(f"  File already exists: {local_filepath}")
                 return {'type': 'file', 'local_path': local_filepath, 'filename': safe_filename, 'final_url': final_url_after_redirects, 'status': 'already_exists'}

            with open(local_filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"  Successfully saved direct download to: {local_filepath}")
            return {'type': 'file', 'local_path': local_filepath, 'filename': safe_filename, 'final_url': final_url_after_redirects, 'status': 'downloaded'}
        
        print(f"  Detected as HTML/page content. Final URL: {final_url_after_redirects}, Content-Type: {content_type}")
        html_text = ""
        try:
            html_text = response.text # Decodes based on headers or chardet
        except Exception as e_text:
            print(f"    Warning: Could not decode response as text: {e_text}.")
            return {'type': 'error', 'message': f"Failed to decode content as text from {url_to_fetch}: {e_text}", 'status_code': response.status_code, 'final_url': final_url_after_redirects}

        return {'type': 'html', 'content': html_text, 'final_url': final_url_after_redirects}

    except requests.exceptions.Timeout:
        return {'type': 'error', 'message': f"Timeout: {url_to_fetch}", 'status_code': None, 'final_url': url_to_fetch}
    except requests.exceptions.HTTPError as http_err:
        status_code = http_err.response.status_code if http_err.response is not None else None
        final_url_on_error = http_err.response.url if http_err.response is not None else url_to_fetch
        print(f"ERROR: HTTP error occurred while fetching {url_to_fetch} (Final URL: {final_url_on_error}): {http_err} (Status code: {status_code})")
        if status_code in [401, 403]: print("This might be due to an expired or incorrect cookie.")
        return {'type': 'error', 'message': f"HTTP error: {http_err}", 'status_code': status_code, 'final_url': final_url_on_error}
    except requests.exceptions.RequestException as req_err:
        return {'type': 'error', 'message': f"Request error: {req_err}", 'status_code': None, 'final_url': url_to_fetch}
    except Exception as e:
        print(f"UNEXPECTED ERROR in fetch_content for {url_to_fetch}: {e}")
        return {'type': 'error', 'message': f"Unexpected error: {e}", 'status_code': None, 'final_url': url_to_fetch}


def get_url_reputation_virustotal(url_to_check):
    # ... (Same as your most recent working version - ensure API key check & error handling) ...
    if not VIRUSTOTAL_API_KEY or "YOUR_ACTUAL_VIRUSTOTAL_API_KEY_HERE" in VIRUSTOTAL_API_KEY:
        print("  WARNING: VirusTotal API key not set. Skipping reputation check.")
        return {"status": "Reputation check skipped (no API key)", "score": None, "details": "N/A"}
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"} # Added Accept
    print(f"  Checking reputation for: {url_to_check} with VirusTotal...")
    time.sleep(16) 
    try:
        response = requests.get(report_url, headers=headers, timeout=20)
        if response.status_code == 404: # Not found in VT DB
            return {"status": "Not found in VT", "score": 0, "details": "URL not yet analyzed or known by VT."}
        response.raise_for_status()
        data = response.json()
        if 'data' in data and 'attributes' in data['data']:
            attributes = data['data']['attributes']; stats = attributes.get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0); suspicious_count = stats.get('suspicious', 0)
            rep_summary = {
                "status": "Unknown", "score": malicious_count + suspicious_count,
                "positives": malicious_count, "suspicious": suspicious_count,
                "total_scans": sum(stats.values()),
                "details_link": f"https://www.virustotal.com/gui/url/{url_id}/detection",
                "last_analysis_date": attributes.get('last_analysis_date') # Unix timestamp
            }
            if malicious_count > 0: rep_summary["status"] = "Malicious"
            elif suspicious_count > 0: rep_summary["status"] = "Suspicious"
            elif sum(stats.values()) > 0 : rep_summary["status"] = "Likely Safe / Clean"
            else: rep_summary["status"] = "No analysis data / Unknown"
            print(f"    VT Status: {rep_summary['status']}, Positives: {malicious_count}, Suspicious: {suspicious_count}")
            return rep_summary
        else: # Should not happen if data['data'] exists due to raise_for_status unless VT changes API for non-error cases
            print(f"    VirusTotal: Unexpected response format for {url_to_check}. Data: {data.get('error', 'No error field') if isinstance(data, dict) else 'Not a dict'}")
            return {"status": "VT Response Format Error", "score": None, "details": "Unexpected JSON structure from VT"}
    except requests.exceptions.HTTPError as http_err:
        status_code = http_err.response.status_code if http_err.response is not None else 'N/A'
        err_details = str(http_err)
        try: # Try to get more details from VT error response
            vt_error_data = http_err.response.json()
            if 'error' in vt_error_data and 'message' in vt_error_data['error']:
                err_details = vt_error_data['error']['message']
        except: pass # Ignore if can't parse JSON error
        print(f"    ERROR checking VirusTotal for {url_to_check}: HTTP {status_code} - {err_details}")
        if status_code == 401: err_details = "API Key Invalid or Missing Permissions"
        elif status_code == 429: err_details = "Too many requests to VT API"
        return {"status": f"Error accessing VT ({status_code})", "score": None, "details": err_details}
    except requests.exceptions.RequestException as req_err: # Timeout, ConnectionError etc.
        print(f"    ERROR checking VirusTotal for {url_to_check}: {req_err}")
        return {"status": "Request Error to VT", "score": None, "details": str(req_err)}
    except Exception as e: # Catch-all for other unexpected issues
        print(f"    UNEXPECTED ERROR checking VirusTotal for {url_to_check}: {e}")
        return {"status": "Unexpected Error with VT", "score": None, "details": str(e)}


def generate_subject_report_csv(subject_name, analyzed_links_data, report_filepath):
    # ... (Same as your most recent working version - ensure CSV headers are good) ...
    if not analyzed_links_data:
        print(f"No analyzed links data to generate report for subject: {subject_name}")
        return
    fieldnames = [
        'Subject', 'Source Page URL', 'Link Text', 'External URL',
        'Reputation Status', 'VT Positives (Malicious)', 'VT Suspicious', 
        'VT Total Scans', 'VT Last Analysis Date', 'VT Details Link'
    ]
    try:
        with open(report_filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for link_item in analyzed_links_data:
                reputation = link_item.get('reputation', {})
                last_analysis_ts = reputation.get('last_analysis_date')
                last_analysis_dt_str = "N/A"
                if last_analysis_ts:
                    try:
                        last_analysis_dt_str = datetime.fromtimestamp(last_analysis_ts).strftime('%Y-%m-%d %H:%M:%S UTC')
                    except Exception as e_dt: 
                        print(f"Warning: Could not parse timestamp {last_analysis_ts}: {e_dt}")
                        last_analysis_dt_str = str(last_analysis_ts) # store as is if parsing fails
                
                writer.writerow({
                    'Subject': subject_name,
                    'Source Page URL': link_item.get('source_page_url', 'N/A'),
                    'Link Text': link_item.get('text', 'N/A'),
                    'External URL': link_item.get('url', 'N/A'),
                    'Reputation Status': reputation.get('status', 'N/A'),
                    'VT Positives (Malicious)': reputation.get('positives', 'N/A'),
                    'VT Suspicious': reputation.get('suspicious', 'N/A'),
                    'VT Total Scans': reputation.get('total_scans', 'N/A'),
                    'VT Last Analysis Date': last_analysis_dt_str,
                    'VT Details Link': reputation.get('details_link', 'N/A')
                })
        print(f"Successfully generated CSV report: {report_filepath}")
    except Exception as e:
        print(f"ERROR: Could not generate CSV report {report_filepath}: {e}")


def save_to_json(data_to_save, filename_base, subject_id_for_file):
    # Save to reports_and_summaries subdir
    reports_dir = os.path.join(DOWNLOAD_DIRECTORY, "reports_and_summaries")
    filepath = os.path.join(reports_dir, f"{filename_base}_{subject_id_for_file}.json")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data_to_save, f, indent=2, ensure_ascii=False) # ensure_ascii=False for non-latin chars
        print(f"Saved data to: {filepath}")
    except Exception as e:
        print(f"ERROR saving {filename_base} to JSON: {e}")

# 4. YOUR MAIN SCRIPT LOGIC (if __name__ == "__main__":) GOES HERE
if __name__ == "__main__":
    print("--- LMS Content Scraper Initializing (Multi-Page Crawler) ---")

    # Basic configuration checks
    if "YOUR_ACTUAL_COOKIE_STRING_HERE" in MY_LMS_COOKIE or \
       "YOUR_ACTUAL_STARTING_MOODLE_COURSE_URL_HERE" in STARTING_COURSE_URL or \
       "YOUR_ACTUAL_VIRUSTOTAL_API_KEY_HERE" in VIRUSTOTAL_API_KEY:
        print("CRITICAL ERROR: Default placeholder values found for cookie, start URL, or API key.")
        print("Please edit the script and replace these placeholders with your actual values.")
        exit()
    if not LMS_SPECIFIC_DOMAIN or LMS_SPECIFIC_DOMAIN == "your.lms.university.edu": # Example check
        print("ERROR: LMS_SPECIFIC_DOMAIN is not set correctly.")
        exit()


    create_download_directory_structure() # Creates main dir and subdirs

    pages_to_visit_queue = [STARTING_COURSE_URL]
    visited_pages = set() # Store final URLs after redirects
    
    subject_all_downloaded_files = []
    subject_all_lms_internal_links_found = [] # For non-content, non-file LMS links
    subject_all_uni_internal_links_found = []   # For non-LMS, non-file Uni links
    subject_all_external_links_raw = {}       # Use dict to store unique external URLs and their first encountered source/text

    MAX_PAGES_TO_CRAWL = 20 # Adjust for testing vs. full run
    pages_crawled_count = 0
    
    # Use a slug from the starting URL for report filenames to identify the "subject"
    parsed_start_url = urlparse(STARTING_COURSE_URL)
    subject_identifier_for_report = f"{parsed_start_url.netloc}_{parsed_start_url.path.replace('/', '_').strip('_')}"
    if not subject_identifier_for_report.replace("_",""): # If it became empty
        subject_identifier_for_report = "moodle_course_main"


    while pages_to_visit_queue and pages_crawled_count < MAX_PAGES_TO_CRAWL:
        current_page_url_to_process = pages_to_visit_queue.pop(0)

        # Check based on final URL after potential redirects from previous fetches
        if current_page_url_to_process in visited_pages: # This check will be more effective if we store final_urls in visited
            print(f"\nSkipping already processed or queued (final URL target): {current_page_url_to_process}")
            continue

        print(f"\n--- ({pages_crawled_count + 1}/{MAX_PAGES_TO_CRAWL}) Processing Page URL: {current_page_url_to_process} ---")
        # Add to visited *before* fetch to handle cases where fetch might redirect to an already visited page
        # However, better to add the *final_url* from fetch_result to visited_pages.
        
        time.sleep(1.5) # Polite delay

        fetch_result = fetch_content(current_page_url_to_process, current_page_url_to_process)
        final_url_of_processed_item = fetch_result.get('final_url', current_page_url_to_process)

        if final_url_of_processed_item in visited_pages:
            print(f"  Final URL {final_url_of_processed_item} was already visited. Skipping further processing.")
            continue
        visited_pages.add(final_url_of_processed_item)
        pages_crawled_count += 1


        if fetch_result['type'] == 'html':
            html_content_from_fetch = fetch_result['content']
            
             # --- MODIFIED HTML SAVING LOGIC ---
            parsed_final_url = urlparse(final_url_of_processed_item)
            
            # Create a base for the directory structure under html_pages
            html_save_dir_base = os.path.join(DOWNLOAD_DIRECTORY, "html_pages", parsed_final_url.netloc)
            os.makedirs(html_save_dir_base, exist_ok=True) # Ensure netloc directory exists

            # Generate a unique and safe directory name for this specific page's content
            # Use a hash of the full URL to ensure uniqueness and fixed length for the problematic part
            import hashlib
            url_hash = hashlib.md5(final_url_of_processed_item.encode('utf-8')).hexdigest()

            # Try to get a somewhat descriptive prefix from the path, but keep it short
            path_prefix = "_".join(parsed_final_url.path.strip('/').split('/')[:2]) # First 2 path segments
            path_prefix = "".join(c for c in path_prefix if c.isalnum() or c in ('_', '-')).rstrip()[:30] # Sanitize & shorten

            page_specific_dir_name = f"{path_prefix}_{url_hash}" if path_prefix else url_hash
            
            page_html_save_dir = os.path.join(html_save_dir_base, page_specific_dir_name)
            os.makedirs(page_html_save_dir, exist_ok=True) # This should now be a much shorter path

            # Save the HTML file as index.html within its unique directory
            full_local_html_path = os.path.join(page_html_save_dir, "index.html")
            
            # Store the original URL alongside or in a manifest for this hash if needed for reference
            # For now, the hash itself is the key identifier for the content of that URL
            manifest_path = os.path.join(page_html_save_dir, "url_reference.txt")
            try:
                with open(manifest_path, "w", encoding="utf-8") as f_manifest:
                    f_manifest.write(final_url_of_processed_item)
            except Exception as e_manifest:
                print(f"Warning: Could not write URL reference for {page_html_save_dir}: {e_manifest}")
            
            try:
                with open(full_local_html_path, "w", encoding="utf-8") as f:
                    f.write(html_content_from_fetch)
                print(f"Saved HTML content to: {full_local_html_path}")
            except Exception as e:
                print(f"ERROR: Could not save HTML to {full_local_html_path}: {e}")
            # --- END OF MODIFIED HTML SAVING LOGIC ---

            soup = BeautifulSoup(html_content_from_fetch, 'html.parser')
            page_specific_new_lms_links_to_visit = set()

            all_a_tags = soup.find_all('a', href=True)
            # print(f"Found {len(all_a_tags)} <a> tags on this HTML page.")

            for i, a_tag in enumerate(all_a_tags):
                raw_href = a_tag['href']
                link_text = a_tag.get_text(strip=True) or "N/A"

                if not raw_href or raw_href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    continue
                
                absolute_url = urljoin(final_url_of_processed_item, raw_href) # Use final URL as base
                parsed_absolute_url = urlparse(absolute_url)
                
                if not parsed_absolute_url.scheme or not parsed_absolute_url.netloc or \
                   parsed_absolute_url.scheme not in ['http', 'https']: # Only process http/https links
                    continue
                
                # --- Link Categorization starts here ---
                is_on_lms_specific_domain = LMS_SPECIFIC_DOMAIN == parsed_absolute_url.netloc
                is_on_uni_root_subdomain = parsed_absolute_url.netloc.endswith(f".{UNIVERSITY_ROOT_DOMAIN}") or \
                                           parsed_absolute_url.netloc == UNIVERSITY_ROOT_DOMAIN
                is_on_other_uni_subdomain = is_on_uni_root_subdomain and not is_on_lms_specific_domain
                
                link_is_file_extension = any(parsed_absolute_url.path.lower().endswith(ext) for ext in DOWNLOADABLE_EXTENSIONS)
                link_is_pluginfile_heuristic = 'pluginfile.php' in parsed_absolute_url.path.lower() and \
                                           any(raw_href.lower().endswith(ext) for ext in DOWNLOADABLE_EXTENSIONS) # check raw_href for pluginfile

                # Decision: If a link *looks like* a file, should we try to download it immediately here,
                # or add it to the main queue and let fetch_content handle it when its turn comes?
                # Current fetch_content is good at determining type. So, add to queue if internal,
                # and let fetch_content sort it out. This avoids duplicate download logic.
                
                if is_on_lms_specific_domain:
                    is_lms_course_content_pattern = any(pattern in parsed_absolute_url.path for pattern in INTERNAL_COURSE_LINK_PATTERNS)
                    is_not_self_page = absolute_url.split('#')[0] != final_url_of_processed_item.split('#')[0]
                    
                    # Add to crawl queue if it's an LMS domain link (course pattern or not),
                    # AND it's not the same page, AND it's not already visited/queued.
                    # We let fetch_content determine if these queued links are HTML or files.
                    if is_not_self_page:
                        if is_lms_course_content_pattern: # Priority to course content links for crawling
                            page_specific_new_lms_links_to_visit.add(absolute_url)
                        elif link_is_file_extension or link_is_pluginfile_heuristic: # Likely a direct file link
                             # We'll let it be queued if unique, fetch_content will download it
                             page_specific_new_lms_links_to_visit.add(absolute_url) # Add potential file URLs to queue too
                        else: # Other LMS specific internal link, not a course pattern, not an obvious file
                            subject_all_lms_internal_links_found.append({
                                "text": link_text, "url": absolute_url, "source_page_url": final_url_of_processed_item
                            })
                
                elif is_on_other_uni_subdomain:
                    # For non-LMS uni links, we usually don't crawl them for course content.
                    # But we should check if they are direct files.
                    if link_is_file_extension:
                        # print(f"  Found potential linked file on uni domain: {absolute_url}. Adding to queue for fetch.")
                        page_specific_new_lms_links_to_visit.add(absolute_url) # Add potential file URLs to queue
                    else:
                        subject_all_uni_internal_links_found.append({
                            "text": link_text, "url": absolute_url, "source_page_url": final_url_of_processed_item
                        })
                
                else: # External link
                    if absolute_url not in subject_all_external_links_raw: # Check if URL already stored
                        subject_all_external_links_raw[absolute_url] = { # Store by URL as key
                            "text": link_text, 
                            "url": absolute_url, # Redundant but good for iteration
                            "source_page_url": final_url_of_processed_item,
                            "found_on_pages": [final_url_of_processed_item] # List of pages where this was found
                        }
                    else: # URL already seen, just add current page to its sources
                        subject_all_external_links_raw[absolute_url]["found_on_pages"].append(final_url_of_processed_item)
            
            # Add newly found unique links to the main queue
            for new_link in page_specific_new_lms_links_to_visit:
                # Check against visited_pages (which stores final_urls) and the current queue content
                # This check for queue is not perfect if redirects occur before actual fetch, but helps a bit
                if new_link not in visited_pages and new_link not in pages_to_visit_queue:
                    pages_to_visit_queue.append(new_link)
            
            print(f"Finished processing links for this HTML page. Queue size: {len(pages_to_visit_queue)}")

        elif fetch_result['type'] == 'file':
            print(f"Page URL {current_page_url_to_process} was a direct file: {fetch_result['local_path']}")
            subject_all_downloaded_files.append({
                "text": fetch_result.get('filename', os.path.basename(fetch_result['local_path'])),
                "url": current_page_url_to_process, # Original URL requested
                "final_url_if_redirected": fetch_result['final_url'],
                "local_path": fetch_result['local_path'],
                "source_page_url": "SELF_DIRECT_DOWNLOAD_FROM_QUEUE" # Indicates the queued URL itself was the file
            })
        
        elif fetch_result['type'] == 'error':
            print(f"Could not process {current_page_url_to_process} (Final URL: {final_url_of_processed_item}): {fetch_result['message']}")
        
    # --- End of Crawling Loop ---
    print(f"\n--- Crawling Complete ---")
    print(f"Total unique pages/resources processed (based on final URLs): {len(visited_pages)}")
    print(f"Total LMS internal utility links recorded: {len(subject_all_lms_internal_links_found)}")
    print(f"Total Uni internal utility links recorded: {len(subject_all_uni_internal_links_found)}")
    print(f"Total unique external link URLs found: {len(subject_all_external_links_raw)}")
    print(f"Total files downloaded: {len(subject_all_downloaded_files)}")

    # --- Convert dict of external links to list for processing ---
    external_links_list_for_analysis = list(subject_all_external_links_raw.values())

    # --- Analyze ALL collected external links (using the list) ---
    subject_all_external_links_with_reputation = []
    if external_links_list_for_analysis:
        print("\n--- Analyzing ALL External Links for Cyber Reputation ---")
        for i, link_info_dict_item in enumerate(external_links_list_for_analysis):
            print(f"Analyzing external link {i+1}/{len(external_links_list_for_analysis)}: {link_info_dict_item['url']}")
            reputation_data = get_url_reputation_virustotal(link_info_dict_item['url'])
            
            # Create a new dict for the output, merging original info and reputation
            analyzed_item = {
                "text": link_info_dict_item['text'],
                "url": link_info_dict_item['url'],
                # For simplicity, take the first source page. In a real report, you might list all.
                "source_page_url": link_info_dict_item['found_on_pages'][0] if link_info_dict_item['found_on_pages'] else 'N/A',
                "all_source_pages": link_info_dict_item['found_on_pages'], # Keep all sources
                "reputation": reputation_data
            }
            subject_all_external_links_with_reputation.append(analyzed_item)
        print("\n--- Cyber Reputation Analysis Complete for All External Links ---")
    else:
        print("No external links found across all crawled pages to analyze.")

    # --- Generate ONE comprehensive report for the "subject" ---
    reports_subdir = os.path.join(DOWNLOAD_DIRECTORY, "reports_and_summaries")
    report_filepath_csv = os.path.join(reports_subdir, f"comprehensive_report_{subject_identifier_for_report}.csv")

    if subject_all_external_links_with_reputation:
        generate_subject_report_csv(
            subject_name=subject_identifier_for_report, 
            analyzed_links_data=subject_all_external_links_with_reputation, 
            report_filepath=report_filepath_csv
        )
    else:
        print("No analyzed external links data to generate comprehensive CSV report.")

    # --- Save all collected data to JSON ---
    save_to_json(subject_all_downloaded_files, "downloaded_files_summary", subject_identifier_for_report)
    save_to_json(subject_all_external_links_with_reputation, "external_links_analyzed_summary", subject_identifier_for_report)
    save_to_json(list(visited_pages), "visited_pages_summary", subject_identifier_for_report) # Convert set to list for JSON
    save_to_json(subject_all_lms_internal_links_found, "lms_internal_links_summary", subject_identifier_for_report)
    save_to_json(subject_all_uni_internal_links_found, "uni_internal_links_summary", subject_identifier_for_report)

    print("\n--- LMS Content Scraper Finished (Multi-Page Crawl with Reputation and Report) ---")