# Dark Web RSS Monitor

A specialized threat intelligence tool that scrapes RSS feeds from dark web hacking forums to find mentions of specific corporate keywords.

### How it works
This script identifies new forum threads and leak listings by parsing XML feeds via the Tor network. It is significantly stealthier than traditional web scraping because it requests only a few hundred lines of XML rather than full HTML pages with tracking scripts.

### Requirements
*   **Python 3.x**
*   **Tor Service:** Must be running locally (Port 9050 or 9150).
*   **Libraries:**
    ```bash
    pip install requests[socks] feedparser
    ```

### Configuration
1.  **Proxies:** If using the Tor Browser instead of the Tor Service, change `TOR_PROXY` to use port `9150`.
2.  **Onion Links:** Populate `TARGET_FEEDS` with current active .onion links found via directories like Ahmia.
3.  **Keywords:** Add your brand names, domains, or specific internal project titles.

### Security Note
For maximum OPSEC, run this on a dedicated Virtual Machine (VM). Ensure you do not accidentally include your own IP in the headers if you modify the user-agent.

### Common RSS Feed URL Patterns
Since dark web URLs change frequently, you can usually guess the RSS endpoint if you know the forum software:
Software	RSS URL Pattern	Used By
MyBB	/syndication.php?limit=20	BreachForums / DarkForums
vBulletin	/external.php?type=RSS2	Exploit.in
XenForo	/forums/-/index.rss or /threads/index.rss	XSS.is / Dread
Invision (IPB)	/index.php?app=core&module=global&section=rss&type=forums&id=1	Various
