# 🎓 LMS External Content Auditor & Localizer (for University) - Still Under Developing

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

*   **Secure LMS Login:** Authenticates with the University LMS to access course content.
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
    *   For localized content, automatically generates academic references (e.g., APA 7th edition, or the University standard) including available metadata like date/time accessed, author (if extractable).
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
*   ** University ToS & Policy:** This tool directly interacts with the University's LMS. Ensure its development and use are aligned with  University's IT policies and the LMS Terms of Service. **Obtain necessary approvals if required.**
*   **Copyright & Fair Use (for Extension Activity):** When copying external content, be acutely aware of copyright laws and fair use principles. This feature should primarily target publicly accessible, open content or content where  University has appropriate licenses.
*   **Third-Party ToS:** Scraping third-party websites also has implications. Be respectful and check their `robots.txt` and ToS.
*   **Data Privacy:** Handle LMS credentials and any scraped student data (if inadvertently encountered) with utmost confidentiality and in compliance with privacy regulations (e.g., FERPA).
*   **Reputation Service API Limits:** Be mindful of API rate limits for the chosen cyber reputation service.
*   **This script is intended for official use by authorized  University personnel.** The developers are not responsible for any misuse or policy violations.

---

## 🛠️ Prerequisites

*   Python 3.8+
*   `pip` (Python package installer)
*   Access credentials for the  University LMS (with appropriate permissions).
*   API Key for the chosen Cyber Reputation Service (e.g., VirusTotal API Key).
*   (For extension activity) A designated local repository/server space for storing cached content.

---

## ⚙️ Installation & Setup

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/rayngnpc/lms-scraper-cookies.git
    cd lms-scraper-cookies
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
4.  LMS Session Cookie Acquisition (Manual Step):
      This script requires active session cookies to interact with the LMS as an authenticated user.          You will need to obtain these manually using your web browser's developer tools.
      a. Navigate to the LMS Login Page:
      Open your web browser (e.g., Chrome, Firefox) and go to the University LMS login page             (e.g., https://uni-lms.example.com).
      b. Open Developer Tools:
      Right-click anywhere on the login page and select "Inspect" or "Inspect Element". This will open        the browser's developer tools panel.
      c. Go to the "Network" Tab:
      In the developer tools panel, find and click on the "Network" tab.
      
      (Consider adding a generic screenshot link or embedding one if your Markdown renderer supports it)
      d. Ensure "Preserve log" (or similar) is checked (Optional but helpful): This ensures network           requests aren't cleared upon page navigation during login.
      
      e. Manually Log In to the LMS:
      On the LMS login page, enter your username and password and click the login button.
      f. Identify a Key Network Request After Login:
      Once you are successfully logged in and redirected to the LMS dashboard or a course page, look at       the list of requests in the "Network" tab. You need to find a request made after successful login.
      This could be a request to a .json endpoint (e.g., ajax.json, dashboard_data.json), an XHR             request, or even the main HTML document request for the page you landed on.
      Click on this request in the list to see its details.
      g. Navigate to the "Cookies" or "Headers" Tab for the Request:
      In the details pane for the selected request:
      Some browsers have a dedicated "Cookies" sub-tab.
      Alternatively, look under the "Headers" sub-tab, then scroll down to the "Request Headers"              section. You are looking for the Cookie: header.
      h. Copy the Cookie String:
      You need to copy the entire string value associated with the Cookie request header. It will look        like a long string of name=value pairs separated by semicolons.
      Example of what to look for (your values will be different):
      Cookie: MoodleSession=a1b2c3d4e5f6; SESSIONID=zyxwvuts; _ga=GA1.2.abcdef.12345;                         user_preference=xyz; ...
      Use code with caution.
      If you see a table format like your example:
         _ga	"GA1.4.14dsdada5.17dasdad42"
         _ga_PMdadsadZB	"GS2.4.sdasdad0$t174731724dsadadh0"
         MoodleSession "a1b2c3d4e5f6"
         Use code with caution.
It's usually easier to find the single Cookie: line in the "Request Headers" section.
i. Paste into raw_cookies.txt:
In the root directory of your cloned project access a file named raw_cookies.txt.
Paste the entire copied cookie string into this file. .

Security Note: This raw_cookies.txt file contains sensitive session information. Ensure it is added to your .gitignore file to prevent it from being accidentally committed to version control. If not already present, add this line to .gitignore:
raw_cookies.txt

---


