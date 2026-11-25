"""
MIRAGE Shield — Website Cloner
Downloads and replicates any target website into a local honeypot clone.
Preserves visual appearance while rewriting asset URLs and preparing deception layers.
"""

import os
import re
import logging
import hashlib
from urllib.parse import urljoin, urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

import mirage_shield.config as shield_cfg

logger = logging.getLogger("MIRAGE.Shield.Cloner")


class SiteCloner:
    """
    Clones a target website's HTML, CSS, images, and JS into a local directory.
    The clone is visually identical to the protected site while being served
    under full deception monitoring.
    """

    def __init__(self, target_url: str, clone_dir: str = None):
        self.target_url = target_url.rstrip("/")
        self.parsed = urlparse(self.target_url)
        self.domain = self.parsed.netloc or "localhost"
        self.clone_dir = clone_dir or shield_cfg.CLONE_DIR
        self.clone_path = os.path.join(self.clone_dir, self._safe_dirname())
        self.session = requests.Session() if requests else None
        self.cloned_pages = {}
        self.cloned_assets = {}
        self.last_status = {
            "target_url": self.target_url,
            "domain": self.domain,
            "pages_count": 0,
            "assets_count": 0,
            "mode": "uninitialized",
            "clone_path": self.clone_path,
        }

        if self.session:
            self.session.headers.update({
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.9",
            })

    def _safe_dirname(self) -> str:
        """Generate a filesystem-safe directory name from the domain."""
        return re.sub(r"[^\w\-.]", "_", self.domain)

    def set_target(self, target_url: str):
        """Switch target URL and reset clone destination."""
        self.target_url = target_url.rstrip("/")
        self.parsed = urlparse(self.target_url)
        self.domain = self.parsed.netloc or "localhost"
        self.clone_path = os.path.join(self.clone_dir, self._safe_dirname())
        self.cloned_pages = {}
        self.cloned_assets = {}

    def clone(self, max_pages: int = 8) -> str:
        """
        Clone the target website up to max_pages internal HTML pages.
        Falls back gracefully to a realistic corporate clone template if the
        target is unreachable or BeautifulSoup/requests are unavailable.
        """
        if not requests or not BeautifulSoup:
            logger.warning("requests/beautifulsoup4 unavailable. Creating fallback corporate clone.")
            return self._create_fallback_clone()

        os.makedirs(self.clone_path, exist_ok=True)
        os.makedirs(os.path.join(self.clone_path, "assets"), exist_ok=True)

        logger.info(f"🪞 Cloning website: {self.target_url}")

        pages_to_clone = [self.target_url]
        pages_cloned = set()

        while pages_to_clone and len(pages_cloned) < max_pages:
            url = pages_to_clone.pop(0)
            if url in pages_cloned:
                continue

            try:
                html, new_links = self._clone_page(url)
                if html:
                    pages_cloned.add(url)
                    for link in new_links:
                        if link not in pages_cloned and link not in pages_to_clone:
                            pages_to_clone.append(link)
            except Exception as e:
                logger.warning(f"Failed to clone {url}: {e}")

        if not pages_cloned:
            logger.warning(f"Target {self.target_url} unreachable during clone; generating fallback clone.")
            return self._create_fallback_clone()

        self.last_status = {
            "target_url": self.target_url,
            "domain": self.domain,
            "pages_count": len(pages_cloned),
            "assets_count": len(self.cloned_assets),
            "mode": "live_clone",
            "clone_path": self.clone_path,
        }
        logger.info(f"✅ Cloned {len(pages_cloned)} pages and {len(self.cloned_assets)} assets")
        return self.clone_path

    def _clone_page(self, url: str) -> tuple:
        """Clone a single page and rewrite its local asset & navigation links."""
        try:
            resp = self.session.get(url, timeout=8, verify=False)
            resp.raise_for_status()
        except Exception as e:
            logger.debug(f"Could not fetch {url}: {e}")
            return None, []

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "<html" not in resp.text[:500].lower():
            return None, []

        soup = BeautifulSoup(resp.text, "html.parser")
        internal_links = []

        # Download & rewrite CSS stylesheets
        for tag in soup.find_all("link", rel=True):
            rels = [r.lower() for r in (tag.get("rel") or [])]
            if "stylesheet" in rels or "icon" in rels:
                href = tag.get("href")
                if href and not href.startswith("data:"):
                    local_path = self._download_asset(urljoin(url, href))
                    if local_path:
                        tag["href"] = f"/mirage-shield/assets/{os.path.basename(local_path)}"

        # Download & rewrite external JS scripts
        for tag in soup.find_all("script", src=True):
            src = tag.get("src")
            if src and not src.startswith("data:"):
                local_path = self._download_asset(urljoin(url, src))
                if local_path:
                    tag["src"] = f"/mirage-shield/assets/{os.path.basename(local_path)}"

        # Download & rewrite images
        for tag in soup.find_all("img", src=True):
            src = tag.get("src")
            if src and not src.startswith("data:"):
                local_path = self._download_asset(urljoin(url, src))
                if local_path:
                    tag["src"] = f"/mirage-shield/assets/{os.path.basename(local_path)}"

        # Collect and rewrite internal links (skip trap endpoints so they stay clean)
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            full_url = urljoin(url, href)
            parsed = urlparse(full_url)
            if parsed.netloc == self.domain:
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
                internal_links.append(clean_url)
                tag["href"] = parsed.path or "/"

        # Ensure <form> actions post back inside our proxy cleanly
        for form in soup.find_all("form"):
            action = form.get("action") or "/login"
            parsed_action = urlparse(urljoin(url, action))
            form["action"] = parsed_action.path or "/login"

        # Save HTML page locally
        rel_path = urlparse(url).path.strip("/") or "index"
        filepath = self._page_path_to_filepath(rel_path)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(str(soup))

        route_key = "/" + urlparse(url).path.strip("/")
        self.cloned_pages[route_key] = filepath
        return str(soup), internal_links

    def _page_path_to_filepath(self, rel_path: str) -> str:
        """Convert URL path to a safe filename under clone_path."""
        safe = re.sub(r"[^\w\-]", "_", rel_path.strip("/") or "index")
        if not safe.endswith(".html"):
            safe += ".html"
        return os.path.join(self.clone_path, safe)

    def resolve_page_path(self, url_path: str) -> str:
        """Resolve an incoming URL path to a cloned HTML file, falling back to index.html."""
        clean = url_path.strip("/") or "index"
        candidate = self._page_path_to_filepath(clean)
        if os.path.exists(candidate):
            return candidate
        index_path = self.get_index_path()
        if os.path.exists(index_path):
            return index_path
        return ""

    def resolve_asset_path(self, filename: str) -> str:
        """Resolve a cloned asset filename safely within the clone assets directory."""
        safe_name = os.path.basename(filename)
        asset_path = os.path.join(self.clone_path, "assets", safe_name)
        if os.path.isfile(asset_path):
            return asset_path
        return ""

    def _download_asset(self, url: str) -> str:
        """Download a CSS/JS/image asset and store locally."""
        if url in self.cloned_assets:
            return self.cloned_assets[url]

        try:
            resp = self.session.get(url, timeout=8, verify=False)
            resp.raise_for_status()

            ext = os.path.splitext(urlparse(url).path)[1] or ".bin"
            if len(ext) > 10:
                ext = ".bin"
            name_hash = hashlib.md5(url.encode()).hexdigest()[:12]
            filename = f"{name_hash}{ext}"
            filepath = os.path.join(self.clone_path, "assets", filename)

            with open(filepath, "wb") as f:
                f.write(resp.content)

            self.cloned_assets[url] = filepath
            return filepath
        except Exception as e:
            logger.debug(f"Could not download asset {url}: {e}")
            return None

    def _create_fallback_clone(self) -> str:
        """Create a realistic corporate portal decoy if target isn't reachable yet."""
        os.makedirs(self.clone_path, exist_ok=True)
        os.makedirs(os.path.join(self.clone_path, "assets"), exist_ok=True)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.domain} — Enterprise Portal</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: linear-gradient(135deg, #0a0e17 0%, #1a1f36 100%);
            color: #e0e0e0; min-height: 100vh;
            display: flex; flex-direction: column; align-items: center;
        }}
        .header {{
            width: 100%; padding: 20px 40px;
            background: rgba(0,0,0,0.35); border-bottom: 1px solid #2d3548;
            display: flex; justify-content: space-between; align-items: center;
        }}
        .logo {{ font-size: 22px; font-weight: bold; color: #00d4ff; }}
        .nav a {{
            color: #a0aec0; text-decoration: none; margin-left: 26px;
            transition: color 0.3s; font-size: 14px;
        }}
        .nav a:hover {{ color: #00d4ff; }}
        .hero {{
            text-align: center; padding: 70px 20px; max-width: 780px;
        }}
        .hero h1 {{ font-size: 42px; margin-bottom: 16px; color: #fff; }}
        .hero p {{ font-size: 17px; color: #a0aec0; line-height: 1.6; }}
        .login-box {{
            background: rgba(255,255,255,0.04); border: 1px solid #2d3548;
            border-radius: 12px; padding: 36px; margin: 36px auto 0;
            width: 390px; max-width: 100%; text-align: left;
            box-shadow: 0 12px 35px rgba(0,0,0,0.4);
        }}
        .login-box h2 {{ margin-bottom: 22px; color: #00d4ff; font-size: 20px; }}
        .login-box input {{
            width: 100%; padding: 12px 14px; margin-bottom: 14px;
            background: rgba(0,0,0,0.35); border: 1px solid #3f4a63;
            border-radius: 8px; color: #fff; font-size: 14px;
        }}
        .login-box button {{
            width: 100%; padding: 13px; background: #00d4ff;
            border: none; border-radius: 8px; color: #000;
            font-size: 15px; font-weight: bold; cursor: pointer;
        }}
        .login-box button:hover {{ background: #00b8d9; }}
        .footer {{
            margin-top: auto; padding: 20px; color: #556; font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🏢 {self.domain}</div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/api/config">API Docs</a>
            <a href="/admin">Employee Portal</a>
            <a href="/backup.sql">Backups</a>
        </div>
    </div>
    <div class="hero">
        <h1>Welcome to {self.domain}</h1>
        <p>Enterprise Workspace &amp; Internal Resource Gateway. Authorized staff sign in below.</p>
        <div class="login-box">
            <h2>🔒 Staff Authentication</h2>
            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="Corporate Email or Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Sign In</button>
            </form>
            <p style="margin-top:14px;color:#718096;font-size:12px;">
                SSO enabled • Protected Gateway v4.2
            </p>
        </div>
    </div>
    <div class="footer">
        &copy; 2026 {self.domain} — Internal Corporate Gateway
    </div>
</body>
</html>"""

        index_path = self.get_index_path()
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html)

        self.cloned_pages = {"/": index_path}
        self.last_status = {
            "target_url": self.target_url,
            "domain": self.domain,
            "pages_count": 1,
            "assets_count": 0,
            "mode": "fallback_template",
            "clone_path": self.clone_path,
        }
        return self.clone_path

    def get_index_path(self) -> str:
        """Return the path to the cloned index.html."""
        return os.path.join(self.clone_path, "index.html")
