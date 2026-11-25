"""
MIRAGE Shield — Website Cloner
Clones any target website's HTML with pixel-perfect visual fidelity by resolving
CSS, fonts, scripts, SVG, and responsive images cleanly against the live origin
while keeping internal links and login forms trapped inside MIRAGE Shield.
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
    Clones a target website into a local honeypot directory.
    Preserves CSS, fonts, images, and responsive srcsets so the decoy
    is visually indistinguishable from the protected origin.
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
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
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

    def clone(self, max_pages: int = 3) -> str:
        """
        Clone the target website (index + key internal pages).
        Falls back cleanly to a corporate portal decoy if offline/unreachable.
        """
        if not requests or not BeautifulSoup:
            logger.warning("requests/beautifulsoup4 unavailable. Creating fallback corporate clone.")
            return self._create_fallback_clone()

        os.makedirs(self.clone_path, exist_ok=True)
        os.makedirs(os.path.join(self.clone_path, "assets"), exist_ok=True)

        logger.info(f"🪞 Cloning website: {self.target_url}")

        pages_to_clone = [self.target_url]
        pages_cloned = set()
        resolved_assets_count = 0

        while pages_to_clone and len(pages_cloned) < max_pages:
            url = pages_to_clone.pop(0)
            if url in pages_cloned:
                continue

            try:
                html, new_links, asset_cnt = self._clone_page(url)
                if html:
                    pages_cloned.add(url)
                    resolved_assets_count += asset_cnt
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
            "assets_count": resolved_assets_count,
            "mode": "live_clone",
            "clone_path": self.clone_path,
        }
        logger.info(f"✅ Cloned {len(pages_cloned)} pages ({resolved_assets_count} assets resolved)")
        return self.clone_path

    def _abs_url(self, base_url: str, raw: str) -> str:
        """Resolve relative asset paths against the live origin URL."""
        if not raw:
            return raw
        val = raw.strip()
        if val.startswith(("#", "data:", "blob:", "mailto:", "tel:", "javascript:")):
            return raw
        return urljoin(base_url, val)

    def _rewrite_srcset(self, base_url: str, srcset_val: str) -> str:
        """Resolve responsive srcset entries against the live origin URL."""
        if not srcset_val:
            return srcset_val
        parts = []
        for item in srcset_val.split(","):
            tokens = item.strip().split()
            if not tokens:
                continue
            tokens[0] = self._abs_url(base_url, tokens[0])
            parts.append(" ".join(tokens))
        return ", ".join(parts)

    def _rewrite_css_urls(self, base_url: str, css_text: str) -> str:
        """Resolve relative url(...) references inside inline CSS."""
        if not css_text:
            return css_text

        def _repl(match):
            quote = match.group(1) or ""
            raw_path = match.group(2).strip()
            if raw_path.startswith(("data:", "http://", "https://", "//", "#")):
                return match.group(0)
            return f"url({quote}{urljoin(base_url, raw_path)}{quote})"

        return re.sub(r"url\((['\"]?)([^)'\"]+)\1\)", _repl, css_text)

    def _clone_page(self, url: str) -> tuple:
        """Fetch page, resolve all visual assets cleanly, and trap links/forms."""
        try:
            resp = self.session.get(url, timeout=8, verify=False, allow_redirects=True)
            resp.raise_for_status()
        except Exception as e:
            logger.debug(f"Could not fetch {url}: {e}")
            return None, [], 0

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "<html" not in resp.text[:500].lower():
            return None, [], 0

        # Use final URL post-redirect (e.g. programiz.com -> https://www.programiz.com/)
        base_url = resp.url or url
        actual_domain = urlparse(base_url).netloc or self.domain
        soup = BeautifulSoup(resp.text, "html.parser")
        internal_links = []
        asset_count = 0

        # Remove strict CSP meta tags so injected beacon/interceptors work cleanly
        for meta in soup.find_all("meta", attrs={"http-equiv": True}):
            if str(meta.get("http-equiv", "")).lower() == "content-security-policy":
                meta.decompose()

        # Remove <base> tags that would hijack trapped form actions/links away from our proxy
        for base_tag in soup.find_all("base"):
            base_tag.decompose()

        # Resolve <link> tags (CSS, preload, icons, fonts) to absolute origin URLs
        for tag in soup.find_all("link", href=True):
            rels = [r.lower() for r in (tag.get("rel") or [])]
            if "canonical" in rels or "alternate" in rels:
                continue
            tag["href"] = self._abs_url(base_url, tag["href"])
            asset_count += 1

        # Resolve <script src> and remove nonce blocking if needed
        for tag in soup.find_all("script", src=True):
            tag["src"] = self._abs_url(base_url, tag["src"])
            asset_count += 1

        # Resolve <img> (src, data-src, srcset)
        for tag in soup.find_all("img"):
            if tag.get("src"):
                tag["src"] = self._abs_url(base_url, tag["src"])
                asset_count += 1
            if tag.get("data-src"):
                abs_data = self._abs_url(base_url, tag["data-src"])
                tag["data-src"] = abs_data
                if not tag.get("src") or tag.get("src", "").startswith("data:"):
                    tag["src"] = abs_data
            if tag.get("srcset"):
                tag["srcset"] = self._rewrite_srcset(base_url, tag["srcset"])

        # Resolve <source>, <video>, <audio>, <use>
        for tag in soup.find_all(["source", "video", "audio", "iframe"]):
            if tag.get("src"):
                tag["src"] = self._abs_url(base_url, tag["src"])
                asset_count += 1
            if tag.get("srcset"):
                tag["srcset"] = self._rewrite_srcset(base_url, tag["srcset"])
            if tag.get("poster"):
                tag["poster"] = self._abs_url(base_url, tag["poster"])

        for tag in soup.find_all("use"):
            if tag.get("href"):
                tag["href"] = self._abs_url(base_url, tag["href"])
            if tag.get("xlink:href"):
                tag["xlink:href"] = self._abs_url(base_url, tag["xlink:href"])

        # Rewrite inline <style> blocks and style="..." attributes
        for style_tag in soup.find_all("style"):
            if style_tag.string:
                style_tag.string.replace_with(self._rewrite_css_urls(base_url, style_tag.string))
        for styled in soup.find_all(style=True):
            styled["style"] = self._rewrite_css_urls(base_url, styled["style"])

        # Keep internal navigation links pointing inside MIRAGE Shield
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            if parsed.netloc in (self.domain, actual_domain):
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
                internal_links.append(clean_url)
                rel = parsed.path or "/"
                if parsed.query:
                    rel = f"{rel}?{parsed.query}"
                tag["href"] = rel

        # Ensure all <form> submissions stay trapped inside MIRAGE Shield
        for form in soup.find_all("form"):
            action = form.get("action") or "/login"
            parsed_action = urlparse(urljoin(base_url, action))
            form["action"] = parsed_action.path or "/login"
            if not form.get("method"):
                form["method"] = "POST"

        # Save cloned HTML page locally
        rel_path = urlparse(url).path.strip("/") or "index"
        filepath = self._page_path_to_filepath(rel_path)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        html_out = str(soup)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_out)

        route_key = "/" + urlparse(url).path.strip("/")
        self.cloned_pages[route_key] = filepath
        return html_out, internal_links, asset_count

    def _page_path_to_filepath(self, rel_path: str) -> str:
        """Convert URL path to a safe filename under clone_path."""
        safe = re.sub(r"[^\w\-]", "_", rel_path.strip("/") or "index")
        if len(safe) > 120:
            safe = safe[:80] + "_" + hashlib.md5(safe.encode()).hexdigest()[:12]
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

    def get_or_clone_page(self, url_path: str) -> str:
        """
        Return the cached cloned HTML file for url_path, or clone that specific
        subpage on-demand from the target origin so clicked links never 404.
        """
        clean = "/" + url_path.strip("/") if url_path and url_path.strip("/") else "/"
        rel = clean.strip("/") or "index"
        candidate = self._page_path_to_filepath(rel)
        if os.path.exists(candidate):
            return candidate

        os.makedirs(self.clone_path, exist_ok=True)
        os.makedirs(os.path.join(self.clone_path, "assets"), exist_ok=True)

        if requests and BeautifulSoup:
            target_page_url = self.target_url if clean == "/" else f"{self.target_url}{clean}"
            html, _, _ = self._clone_page(target_page_url)
            if html and os.path.exists(candidate):
                return candidate

        return self.resolve_page_path(clean)

    def apply_portal_prefix(self, html: str, prefix: str) -> str:
        """Rewrite internal <a> links and <form> actions under a clean /portal/<domain> prefix."""
        clean_prefix = "/" + prefix.strip("/")
        if not BeautifulSoup or not html:
            return html

        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith("/") and not href.startswith("//") and not href.startswith(clean_prefix):
                tag["href"] = clean_prefix if href == "/" else f"{clean_prefix}{href}"

        for form in soup.find_all("form"):
            action = (form.get("action") or "/login").strip()
            if action.startswith("/") and not action.startswith("//") and not action.startswith(clean_prefix):
                form["action"] = f"{clean_prefix}{action}"

        return str(soup)

    def resolve_asset_path(self, filename: str) -> str:
        """Resolve a cloned asset filename safely within the clone assets directory."""
        safe_name = os.path.basename(filename)
        asset_path = os.path.join(self.clone_path, "assets", safe_name)
        if os.path.isfile(asset_path):
            return asset_path
        return ""

    def _download_asset(self, url: str) -> str:
        """Optional helper to download a CSS/JS/image asset locally."""
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
        .hero {{ text-align: center; padding: 70px 20px; max-width: 780px; }}
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
        .footer {{ margin-top: auto; padding: 20px; color: #556; font-size: 12px; }}
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
    <div class="footer">&copy; 2026 {self.domain} — Internal Corporate Gateway</div>
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
