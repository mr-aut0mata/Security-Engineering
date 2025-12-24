import feedparser
import requests
import time
import os

# --- CONFIGURATION ---
# Tor Proxy Settings (9050 for Service, 9150 for Tor Browser)
TOR_PROXY = "socks5h://127.0.0.1:9050" 

# Keywords to monitor (use brand names, internal project names, or unique IDs)
KEYWORDS = ["MyCompanyName", "mycompany.com", "ProjectAlpha_Leak"]

# RSS Feed URL Patterns for common forum software
# Replace 'domain.onion' with real active onion links
TARGET_FEEDS = [
    "http://breach-forums.onion/syndication.php?limit=20", # MyBB Pattern
    "http://exploit_in.onion/external.php?type=RSS2",      # vBulletin Pattern
    "http://xss_forum.onion/forums/-/index.rss",          # XenForo Pattern
    "http://some-leak-site.onion/feed/"                    # Standard WordPress/Blog
]

def get_tor_session():
    session = requests.Session()
    session.proxies = {'http': TOR_PROXY, 'https': TOR_PROXY}
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0"})
    return session

def monitor_feeds():
    session = get_tor_session()
    
    # Test connection
    try:
        session.get("http://httpbin.org/ip", timeout=15)
        print("[*] Tor Connection Established.")
    except:
        print("[!] Tor is not detected. Please start the Tor service.")
        return

    while True:
        print(f"\n[*] Starting Scan at {time.strftime('%H:%M:%S')}...")
        
        for url in TARGET_FEEDS:
            try:
                # Fetch raw XML via Tor
                response = session.get(url, timeout=30)
                
                # Parse the XML content
                feed = feedparser.parse(response.content)
                
                if feed.bozo:
                    print(f"[-] Could not parse feed: {url}")
                    continue

                print(f"[*] Checking {len(feed.entries)} entries from: {feed.feed.get('title', url)}")

                for entry in feed.entries:
                    content = (entry.get('title', '') + " " + entry.get('summary', '')).lower()
                    
                    for word in KEYWORDS:
                        if word.lower() in content:
                            print(f"\n[!!!] ALERT: Keyword '{word}' found!")
                            print(f"Title: {entry.title}")
                            print(f"Link:  {entry.link}")
                            print("-" * 30)

            except Exception as e:
                print(f"[!] Connection Error with {url}: {e}")

        print("[*] Scan complete. Resting for 30 minutes...")
        time.sleep(1800) 

if __name__ == "__main__":
    monitor_feeds()
