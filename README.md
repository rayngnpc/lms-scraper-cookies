# 🎓 LMS External Content Auditor & Localizer (for Mercy University)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A specialized tool designed for University to scrape its Learning Management System (LMS) environment. It discovers all embedded and linked course materials, analyzes them for external/third-party references, assesses these references against cyber reputation services, and generates reports for LMS subject owners. It also includes an extension to locally cache and reference external content appropriately.

<!-- Optional: Add a GIF or Screenshot -->
<!-- ![LMS Auditor Demo](link_to_your_demo_image_or_gif.gif) -->

---

## 🎯 Core Problem Addressed

Learning Management Systems (LMS) at institutions like University often contain links and references to third-party websites and resources. These external sites represent uncontrolled content, posing potential risks (malware, inappropriate material, poor reputation) and challenges for content stability and academic referencing. This tool aims to mitigate these issues.

---

## 🌟 Features

**Core Functionality:**

*   **Secure LMS Login:** Authenticates with the Mercy University LMS to access course content.
*   **Comprehensive Content Discovery:**
    *   Scrapes specified LMS courses to identify all embedded and linked materials (e.g., PDFs, Word documents, PowerPoints, web links, embedded videos).
    *   Parses discovered materials (documents, HTML pages) to extract all external/third-party URL references.
*   **External Reference Analysis:**
    *   Categorizes and summarizes all unique external references found per LMS subject.
    *   Integrates with a cyber reputation service (e.g., VirusTotal, Google Safe Browsing API - *specify which one you'll use*) to assess the risk (malware, bad content, poor reputation) associated with each external URL.
*   **Subject-Specific Reporting:**
    *   Generates detailed reports for each LMS subject owner.
    *   Reports include:
        *   A list of all external links found within their subject's content.
        *   The cyber reputation assessment for each link.
        *   The original location (e.g., specific document, page name) of the reference within the LMS content.

**Extension Activity Features (Advanced):**

*   **Content Localization & Repository Management:**
    *   Optionally copies publicly accessible external content (e.g., articles, images) to a controlled local repository.
    *   Modifies the LMS content to point to this locally stored version.
*   **Academic Referencing:**
    *   For localized content, automatically generates academic references (e.g., APA 7th edition, or the Mercy University standard) including available metadata like date/time accessed, author (if extractable).
    *   Embeds these references alongside the localized content in the LMS.
*   **Original Link Preservation & Warnings:**
    *   Maintains a clearly marked link to the original external material for verification and authentication by the end-user.
    *   For links pointing to paywalled or controlled-access third-party sites (where content cannot be legally copied locally):
        *   Does *not* copy the content.
        *   Instead, presents a prominent warning message to the LMS user about accessing third-party content before redirecting or providing the direct link.

**General Features:**

*   **Organized Output:** Saves downloaded materials, reports, and logs in a structured directory format.
*   **Configurable:** Easily set up LMS credentials, target courses, download paths, API keys, and reporting preferences via a `config.yaml` file.
*   **Respectful Scraping:** Implements configurable delays between requests to avoid overloading the LMS or external servers.

---

## ❗ Ethical Use, ToS & Data Handling

**VERY IMPORTANT:**
*   **Mercy University ToS & Policy:** This tool directly interacts with the University's LMS. Ensure its development and use are aligned with Mercy University's IT policies and the LMS Terms of Service. **Obtain necessary approvals if required.**
*   **Copyright & Fair Use (for Extension Activity):** When copying external content, be acutely aware of copyright laws and fair use principles. This feature should primarily target publicly accessible, open content or content where Mercy University has appropriate licenses.
*   **Third-Party ToS:** Scraping third-party websites also has implications. Be respectful and check their `robots.txt` and ToS.
*   **Data Privacy:** Handle LMS credentials and any scraped student data (if inadvertently encountered) with utmost confidentiality and in compliance with privacy regulations (e.g., FERPA).
*   **Reputation Service API Limits:** Be mindful of API rate limits for the chosen cyber reputation service.
*   **This script is intended for official use by authorized Mercy University personnel.** The developers are not responsible for any misuse or policy violations.

---

## 🛠️ Prerequisites

*   Python 3.8+
*   `pip` (Python package installer)
*   Access credentials for the Mercy University LMS (with appropriate permissions).
*   API Key for the chosen Cyber Reputation Service (e.g., VirusTotal API Key).
*   (For extension activity) A designated local repository/server space for storing cached content.

---

## ⚙️ Installation & Setup

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/YourUsername/MercyU-LMS-Auditor.git
    cd MercyU-LMS-Auditor
    ```

2.  **Create and Activate a Virtual Environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Linux/macOS
    # venv\Scripts\activate   # On Windows
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(You will need to add libraries for document parsing like `python-docx`, `pypdf2` or `pdfminer.six`, `openpyxl`, etc. to your `requirements.txt` depending on the file types you need to analyze).*

4.  **Configuration (`config.yaml`):**
    *   Rename `config.example.yaml` to `config.yaml`.
    *   Open `config.yaml` and configure:
    ```yaml
    lms:
      base_url: "https://mercyuni-lms.example.com" # Mercy University's LMS URL
      username: "LMS_SERVICE_ACCOUNT_USERNAME" # Use a dedicated service account if possible
      password: "LMS_SERVICE_ACCOUNT_PASSWORD" # Consider environment variables

    # Cyber Reputation Service (e.g., VirusTotal)
    reputation_service:
      name: "VirusTotal" # or "GoogleSafeBrowsing", etc.
      api_key: "YOUR_REPUTATION_SERVICE_API_KEY" # Consider environment variables

    scraper_settings:
      output_base_path: "./LMS_Audit_Output"
      courses_to_audit: # List specific course IDs or names, or a pattern to discover them
        - "COURSE101"
        - "Intro to Subject X"
      file_types_to_parse: [".pdf", ".docx", ".pptx", ".html", ".txt"] # File types to scan for external links
      delay_between_requests: 3 # seconds

    # Extension Activity Settings (if enabled)
    localization:
      enabled: false # Set to true to enable content localization
      local_repository_path: "/mnt/lms_cached_content/" # Path to store copied content
      academic_referencing_style: "APA7" # Or Mercy Uni's standard
      warn_on_paywall: true

    reporting:
      report_format: "csv" # or "html", "pdf"
      email_reports_to_owners: false # If true, need SMTP settings
    # smtp_settings:
    #   server: "smtp.mercy.edu"
    #   port: 587
    #   username: "..."
    #   password: "..."
    ```

---

## 🚀 Usage

```bash
python main_auditor.py [options]
Use code with caution.
Markdown
Examples:
Run full audit for configured courses:
python main_auditor.py
Use code with caution.
Bash
Audit specific courses and enable localization:
python main_auditor.py --courses "BIOL205" "CHEM110" --localize
Use code with caution.
Bash
Generate reports only (assuming previous scan data exists):
python main_auditor.py --generate-reports-only
Use code with caution.
Bash
Get help:
python main_auditor.py --help
Use code with caution.
Bash
(Implement argument parsing using argparse or click in your Python script.)
📄 Output & Reports
The tool will generate:
Log files: Detailed logs of the scraping and analysis process.
Per-Subject Audit Reports: (e.g., COURSE101_External_Links_Audit.csv) containing:
LMS_Content_Item: Name/Path of the LMS item where the link was found.
Original_External_URL: The third-party URL.
Reputation_Score: (e.g., VirusTotal positives/total).
Reputation_Service_Link: Link to the detailed report on the reputation service.
Status: (e.g., "Safe", "Suspicious", "Malicious", "Unknown", "Localized").
Localized_Content_Path: (If localized) Path to the content in the local repository.
Academic_Reference: (If localized) Generated reference.
Localized Content Repository: (If extension activity is enabled) A structured directory containing copies of external content.
Summary Report: An overall summary of findings across all audited subjects.
Example Report Snippet (CSV):
LMS_Content_Item,Original_External_URL,Reputation_Score,Reputation_Service_Link,Status,Localized_Content_Path,Academic_Reference
"Week 3 Lecture Notes.pdf","http://example-resource.com/article.pdf","0/70","vt.com/xyz","Localized","/mnt/lms_cached_content/COURSE101/article.pdf","Author, A. (2023). Article Title. Retrieved from http://example-resource.com/article.pdf (Accessed YYYY-MM-DD)"
"Introduction Page","http://suspicious-site.net/download.exe","15/70","vt.com/abc","Malicious","N/A","N/A"
"Further Reading List","http://journal-behind-paywall.com/paper","N/A (Paywall)","N/A","Warning Displayed","N/A","N/A"
Use code with caution.
Csv
🛠️ Key Libraries to Use
Beyond the initial list, you'll likely need:
Requests, BeautifulSoup4, PyYAML: (As before)
Document Parsers:
PyPDF2 or pdfminer.six for PDFs.
python-docx for .docx files.
python-pptx for .pptx files (extracting links can be tricky).
openpyxl for Excel files if they contain links.
URL Parsing & Validation: urllib.parse, possibly validators library.
API Clients: Specific client libraries for the chosen cyber reputation service (e.g., virustotal-api for VirusTotal v3).
Academic Referencing: Libraries like citeproc-py (complex) or custom logic for APA7.
Command-line Interface: argparse (standard library) or click (more user-friendly).
(Ensure these are added to requirements.txt)
(The "Contributing", "License", and "Contact" sections can remain similar to the previous template, but ensure the Project Link and any contact info are correct for this specific project.)
**Key Changes and Considerations from your new requirements:**

1.  **Project Name & Purpose:** Clearly identifies it as an "Auditor & Localizer" for Mercy University.
2.  **Core Problem Statement:** Added this to give context.
3.  **Features Section Restructured:** Separated into "Core Functionality" and "Extension Activity Features" to match your problem description. Each point is now much more specific.
4.  **Ethical Use Section Enhanced:** Added specific warnings about Mercy University ToS, Copyright, and FERPA, which are critical for a tool like this in an educational institution.
5.  **Prerequisites:** Added "API Key for Cyber Reputation Service" and "local repository space."
6.  **Installation (`requirements.txt` note):** Highlighted the need for document parsing libraries.
7.  **Configuration (`config.yaml`):** Significantly expanded to include settings for:
    *   Cyber reputation service (name, API key).
    *   File types to parse.
    *   Localization settings (enable, repo path, referencing style, paywall warning).
    *   Reporting (format, optional email).
8.  **Usage:** Updated example commands to reflect potential new options like `--localize`.
9.  **Output & Reports:** Detailed the expected report content and structure, including fields like `Localized_Content_Path` and `Academic_Reference`.
10. **Key Libraries to Use:** Added a section suggesting specific libraries for document parsing, API clients, and academic referencing, as these are crucial for the new features.

This revised README should provide a very clear and comprehensive overview of your project, its specific goals for Mercy University, and how to set it up and use it. Remember to continuously update it as your project evolves!
