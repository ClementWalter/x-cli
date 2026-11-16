#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "click==8.4.2",
#     "requests==2.34.2",
#     "pycryptodome==3.23.0",
#     "beautifulsoup4==4.14.2",
#     "XClientTransaction==1.0.3",
# ]
#
# [tool.uv]
# exclude-newer = "2026-11-16T00:00:00Z"
# ///
"""x-cli — read X (Twitter) from the terminal: likes, bookmarks, timelines.

Read-only by design. It speaks the private GraphQL API the x.com web app uses,
as the signed-in user:

* **Session**: the `auth_token` + `ct0` cookies, decrypted from a local
  Chromium browser (Chrome/Arc/Brave/Edge) with the macOS keychain key, so
  nothing is pasted. `X_AUTH_TOKEN` / `X_CT0` override.
* **Query ids and feature flags** rotate with every web deploy, so they are
  scraped from the live web bundle (main.js plus the lazily loaded chunks that
  hold Bookmarks and Home) and cached for a few hours; a 404 refreshes them.
* **x-client-transaction-id**: some endpoints (SearchTimeline) answer 404
  without it. It is derived from the home page and the `ondemand.s` chunk by
  the XClientTransaction library and sent on every call.
"""

from __future__ import annotations

import concurrent.futures
import glob
import hashlib
import hmac
import json as jsonlib
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import bs4
import click
import requests
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

log = logging.getLogger("x-cli")

CONFIG_PATH = Path.home() / ".config" / "x-cli" / "config.json"
CACHE_DIR = Path.home() / ".cache" / "x-cli"
WEB_CACHE = CACHE_DIR / "web.json"
# Query ids live as long as a web deploy; a stale id answers 404 and triggers a refresh.
WEB_CACHE_TTL = 6 * 3600
ASSETS = "https://abs.twimg.com/responsive-web/client-web"
UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)
TIMEOUT = 30
MAX_PAGES = 400  # 400 x 20 = 8000 tweets; reaching it is an error, never a silent cut
PAGE_SIZE = 20

# Operations that are not in main.js, and the substring of the lazy chunk holding them.
CHUNK_HINTS = {
    "Bookmarks": "Bookmark",
    "BookmarkFoldersSlice": "Bookmark",
    "BookmarkFolderTimeline": "Bookmark",
    "HomeTimeline": "HomeTimeline",
    "HomeLatestTimeline": "HomeTimeline",
}

# (label, cookie-store glob, keychain service holding the AES key)
COOKIE_SOURCES = [
    ("chrome", "~/Library/Application Support/Google/Chrome/*/Cookies", "Chrome Safe Storage"),
    ("arc", "~/Library/Application Support/Arc/User Data/*/Cookies", "Arc Safe Storage"),
    ("brave", "~/Library/Application Support/BraveSoftware/Brave-Browser/*/Cookies", "Brave Safe Storage"),
    ("edge", "~/Library/Application Support/Microsoft Edge/*/Cookies", "Microsoft Edge Safe Storage"),
]

NO_SESSION_MESSAGE = (
    "Not signed in to X. Sign in at https://x.com in Chrome, Arc, Brave or Edge on this Mac, then retry: "
    "the session is read from the browser. If macOS asks to allow access to \"Chrome Safe Storage\" "
    "(or your browser's), click Always Allow. In a terminal: `x login`."
)


# --------------------------------------------------------------------------- #
# Browser cookies
# --------------------------------------------------------------------------- #
def _keychain_key(service: str) -> bytes | None:
    """Chromium's macOS cookie key: PBKDF2 of the keychain secret."""
    try:
        proc = subprocess.run(
            ["security", "find-generic-password", "-w", "-s", service],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return PBKDF2(proc.stdout.strip().encode(), b"saltysalt", 16, count=1003,
                  prf=lambda p, s: hmac.new(p, s, hashlib.sha1).digest())


def decrypt_cookie(encrypted: bytes, key: bytes) -> str | None:
    """Decrypt a Chromium `v10`/`v11` AES-CBC cookie value."""
    if not encrypted or encrypted[:3] not in (b"v10", b"v11"):
        return None
    try:
        dec = AES.new(key, AES.MODE_CBC, iv=b" " * 16).decrypt(encrypted[3:])
        dec = dec[: -dec[-1]]
    except (ValueError, IndexError):
        return None
    try:
        return dec.decode()
    except UnicodeDecodeError:
        # Chrome >= M118 prefixes a 32-byte sha256(domain).
        return dec[32:].decode(errors="replace")


def _read_store(store: Path) -> list[tuple[str, bytes]]:
    """(name, encrypted_value) of the x.com cookies in one store."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td) / "Cookies"
        try:
            shutil.copy2(store, tmp)  # the live DB is locked by the browser
            con = sqlite3.connect(f"file:{tmp}?immutable=1", uri=True)
            rows = con.execute(
                "SELECT name, encrypted_value FROM cookies WHERE host_key = '.x.com' "
                "AND name IN ('auth_token', 'ct0', 'twid')"
            ).fetchall()
            con.close()
        except (OSError, sqlite3.Error):
            return []
    return [(n, bytes(v)) for n, v in rows]


def uid_from_twid(twid: str) -> str | None:
    """`twid` is `u=<user id>`, URL-encoded."""
    m = re.fullmatch(r"u=(\d+)", urllib.parse.unquote(twid or "").strip('"'))
    return m.group(1) if m else None


def browser_sessions(source: str | None = None) -> list[dict]:
    """Every x.com session in local browsers, one per (browser profile)."""
    out = []
    for label, pattern, service in COOKIE_SOURCES:
        if source and label != source:
            continue
        stores = sorted(glob.glob(os.path.expanduser(pattern)))
        stores = [s for s in stores if _read_store(Path(s))]
        if not stores:
            continue
        key = _keychain_key(service)  # only ask the keychain for a store holding the cookie
        if not key:
            log.warning("could not read the %s key from the keychain; skipping %s", service, label)
            continue
        for store in stores:
            ck = {n: decrypt_cookie(v, key) for n, v in _read_store(Path(store))}
            if ck.get("auth_token") and ck.get("ct0"):
                out.append({
                    "browser": label,
                    "profile": Path(store).parent.name,
                    "auth_token": ck["auth_token"],
                    "ct0": ck["ct0"],
                    "user_id": uid_from_twid(ck.get("twid") or ""),
                })
    return out


# --------------------------------------------------------------------------- #
# Config and the credential vault contract
# --------------------------------------------------------------------------- #
def env_value(name: str) -> str | None:
    """An env var, treating Claude Desktop's unfilled `${user_config.…}` as unset."""
    value = (os.environ.get(name) or "").strip()
    return None if not value or value.startswith("${") else value


def broker_helper() -> str:
    """Path of the optional `claudine-secret` vault broker."""
    return shutil.which("claudine-secret") or str(Path.home() / ".local/bin/claudine-secret")


def auth_broker(operation: str, config: dict | None = None) -> dict:
    """Talk to the vault broker; credentials travel on stdin, never argv."""
    args = [broker_helper(), "auth", operation, "x"]
    if operation == "status":
        args.append("--json")
    try:
        result = subprocess.run(
            args, input=jsonlib.dumps(config) if config is not None else None,
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if result.returncode not in (0, 3) or not result.stdout.strip():
        return {}
    if operation == "load" and result.returncode != 0:
        return {}
    try:
        payload = jsonlib.loads(result.stdout)
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def load_config() -> dict:
    """Pending local login first, then the vault, then the local copy."""
    pending = CONFIG_PATH.with_suffix(".pending")
    if pending.exists() and CONFIG_PATH.exists():
        return jsonlib.loads(CONFIG_PATH.read_text())
    vault = auth_broker("load")
    if vault:
        return vault
    if CONFIG_PATH.exists():
        try:
            return jsonlib.loads(CONFIG_PATH.read_text())
        except ValueError:
            return {}
    return {}


def save_config(cfg: dict) -> None:
    """Atomic chmod-600 write, then a best-effort vault sync."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    marker = CONFIG_PATH.with_suffix(".pending")
    marker.touch(mode=0o600)
    fd, tmp = tempfile.mkstemp(prefix=".auth-", dir=CONFIG_PATH.parent)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(jsonlib.dumps(cfg, indent=2) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONFIG_PATH)
    finally:
        Path(tmp).unlink(missing_ok=True)
    if not Path(broker_helper()).exists():
        marker.unlink(missing_ok=True)  # no vault on this machine: the local file is the source
        return
    meta = auth_broker("save", cfg)
    if meta.get("source") == "vault" and not meta.get("pending"):
        marker.unlink(missing_ok=True)
    else:
        log.warning("session saved locally; vault synchronization is pending (`x auth-sync`)")


# --------------------------------------------------------------------------- #
# Web bundle: query ids, feature switches, transaction-id material
# --------------------------------------------------------------------------- #
_OP_RE = re.compile(
    r'queryId:"([^"]+)",operationName:"([^"]+)",operationType:"([^"]+)",'
    r'metadata:\{featureSwitches:\[([^\]]*)\](?:,fieldToggles:\[([^\]]*)\])?'
)


def parse_operations(js: str) -> dict:
    """{operationName: {query_id, type, features, toggles}} from a web bundle."""
    ops = {}
    for qid, name, kind, feats, toggles in _OP_RE.findall(js):
        ops[name] = {
            "query_id": qid,
            "type": kind,
            "features": [f.strip('"') for f in feats.split(",") if f],
            "toggles": [f.strip('"') for f in (toggles or "").split(",") if f],
        }
    return ops


def parse_switches(html: str) -> dict:
    """Feature-switch values the web app ships in its initial state."""
    return {m.group(1): m.group(2) == "true"
            for m in re.finditer(r'"([a-z0-9_]+)":\{"value":(true|false)\}', html)}


def chunk_urls(html: str, keyword: str) -> list[str]:
    """URLs of the lazy webpack chunks whose name contains `keyword`."""
    names = dict(re.findall(r'(\d+):"((?:bundle|shared~bundle)[^"]*)"', html))
    hashes = dict(re.findall(r'(\d+):"([0-9a-f]{16})"', html))
    # The chunk file name is `<name>.<hash>a.js` (the `a` suffix is part of the build).
    return sorted(f"{ASSETS}/{n}.{hashes[i]}a.js" for i, n in names.items() if keyword in n and i in hashes)


class Web:
    """Scraped web-app material, cached on disk for WEB_CACHE_TTL."""

    def __init__(self, session: requests.Session, use_cache: bool = True):
        self.s = session
        self.data = self._load() if use_cache else None
        if self.data is None:
            self.refresh()
        self._ct = None

    def _load(self) -> dict | None:
        try:
            data = jsonlib.loads(WEB_CACHE.read_text())
        except (OSError, ValueError):
            return None
        if time.time() - data.get("fetched_at", 0) > WEB_CACHE_TTL:
            return None
        return data

    def refresh(self) -> None:
        """Re-scrape x.com: home page, main.js, ondemand.s, Bookmark/Home chunks."""
        t0 = time.time()
        html = _get(self.s, "https://x.com/home").text
        mains = re.findall(rf"{re.escape(ASSETS)}/main\.[0-9a-z]+\.js", html)
        if not mains:
            raise click.ClickException("x.com home page has no main.js link; the web app changed, update x-cli")
        js = _get(self.s, mains[0]).text
        bearer = re.search(r'"(AAAAAAAAAAAAAAAAAAAAA[^"]+)"', js)
        if not bearer:
            raise click.ClickException("no bearer token in main.js; the web app changed, update x-cli")
        urls = sorted({u for kw in set(CHUNK_HINTS.values()) for u in chunk_urls(html, kw)})
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            extra = list(ex.map(lambda u: _get(self.s, u).text, urls))
        ops = parse_operations(js)
        for chunk in extra:
            ops.update({k: v for k, v in parse_operations(chunk).items() if k not in ops})
        ondemand = self._ondemand_text(html)
        self.data = {
            "fetched_at": time.time(),
            "bearer": bearer.group(1),
            "ops": ops,
            "switches": parse_switches(html),
            "home_html": html,
            "ondemand": ondemand,
        }
        log.debug("web bundle scraped in %.1fs: %d operations", time.time() - t0, len(ops))
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            WEB_CACHE.write_text(jsonlib.dumps(self.data))
        except OSError as e:  # a cache failure never fails a read
            log.debug("web cache not written: %s", e)
        self._ct = None

    def _ondemand_text(self, html: str) -> str:
        from x_client_transaction.utils import get_ondemand_file_url

        url = get_ondemand_file_url(response=bs4.BeautifulSoup(html, "html.parser"))
        if not url:
            raise click.ClickException("no ondemand.s chunk on x.com; the web app changed, update x-cli")
        return _get(self.s, url).text

    def op(self, name: str) -> dict:
        try:
            return self.data["ops"][name]
        except KeyError:
            raise click.ClickException(
                f"operation {name} not found in the x.com web bundle; retry with --no-cache, else update x-cli"
            ) from None

    def transaction_id(self, method: str, path: str) -> str:
        from x_client_transaction import ClientTransaction

        if self._ct is None:
            self._ct = ClientTransaction(
                home_page_response=bs4.BeautifulSoup(self.data["home_html"], "html.parser"),
                ondemand_file_response=self.data["ondemand"],
            )
        return self._ct.generate_transaction_id(method=method, path=path)


def _get(s: requests.Session, url: str) -> requests.Response:
    r = s.get(url, timeout=TIMEOUT)
    if r.status_code != 200:
        raise click.ClickException(f"GET {url} answered {r.status_code}")
    return r


# --------------------------------------------------------------------------- #
# GraphQL client
# --------------------------------------------------------------------------- #
class X:
    """Signed-in GraphQL client for x.com."""

    def __init__(self, auth_token: str, ct0: str, use_cache: bool = True, on_expired=None):
        # Called once when the session is rejected; returns fresh (auth_token, ct0) or None.
        self.on_expired = on_expired
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        self.s.cookies.set("auth_token", auth_token, domain=".x.com")
        self.s.cookies.set("ct0", ct0, domain=".x.com")
        self.web = Web(self.s, use_cache)
        self.s.headers.update({
            "authorization": f"Bearer {self.web.data['bearer']}",
            "x-csrf-token": ct0,
            "x-twitter-auth-type": "OAuth2Session",
            "x-twitter-active-user": "yes",
            "x-twitter-client-language": "en",
            "content-type": "application/json",
            "referer": "https://x.com/",
        })

    def gql(self, name: str, variables: dict, _retry: bool = True) -> dict:
        """Call one GraphQL operation; refreshes stale query ids once."""
        op = self.web.op(name)
        path = f"/i/api/graphql/{op['query_id']}/{name}"
        switches = self.web.data["switches"]
        features = {f: switches.get(f, False) for f in op["features"]}
        # Article plain text lets long-form posts come back as readable text.
        toggles = {t: t == "withArticlePlainText" for t in op["toggles"]}
        for attempt in range(4):
            headers = {"x-client-transaction-id": self.web.transaction_id(
                "POST" if op["type"] == "mutation" else "GET", path)}
            if name in ("HomeTimeline", "HomeLatestTimeline"):
                r = self.s.post(f"https://x.com{path}", headers=headers, timeout=TIMEOUT, json={
                    "variables": variables, "features": features,
                    "fieldToggles": toggles, "queryId": op["query_id"]})
            else:
                r = self.s.get(f"https://x.com{path}", headers=headers, timeout=TIMEOUT, params={
                    "variables": jsonlib.dumps(variables, separators=(",", ":")),
                    "features": jsonlib.dumps(features, separators=(",", ":")),
                    "fieldToggles": jsonlib.dumps(toggles, separators=(",", ":")),
                })
            log.debug("%s %s remaining=%s", name, r.status_code, r.headers.get("x-rate-limit-remaining"))
            if r.status_code == 429:
                reset = int(r.headers.get("x-rate-limit-reset") or 0)
                wait = max(1, reset - int(time.time())) if reset else 2 ** attempt
                if wait > 90:
                    at = datetime.fromtimestamp(reset, timezone.utc).strftime("%H:%M UTC")
                    raise click.ClickException(f"429 — {name} rate limit reached; it resets at {at}")
                log.warning("429 on %s; waiting %ss", name, wait)
                time.sleep(wait)
                continue
            if r.status_code >= 500:
                time.sleep(2 ** attempt)
                continue
            break
        if r.status_code == 404 and _retry:
            log.info("query ids look stale; re-scraping the x.com web bundle")
            self.web.refresh()
            return self.gql(name, variables, _retry=False)
        if r.status_code in (401, 403):
            fresh = self.on_expired() if self.on_expired else None
            if fresh:
                self.on_expired = None
                self.s.cookies.set("auth_token", fresh[0], domain=".x.com")
                self.s.cookies.set("ct0", fresh[1], domain=".x.com")
                self.s.headers["x-csrf-token"] = fresh[1]
                return self.gql(name, variables, _retry)
            raise SessionExpired(f"{r.status_code} — the X session was rejected. {NO_SESSION_MESSAGE}")
        if r.status_code != 200:
            raise click.ClickException(f"{name}: HTTP {r.status_code} {r.text[:200]}")
        data = r.json()
        errors = data.get("errors")
        if errors and not data.get("data"):
            msg = "; ".join(e.get("message", "?") for e in errors)
            if any(e.get("code") in (32, 89, 239) for e in errors):
                raise SessionExpired(msg)
            raise click.ClickException(f"{name}: {msg}")
        return data

    # -- helpers ----------------------------------------------------------- #
    def viewer(self) -> dict:
        data = self.gql("Viewer", {"withCommunitiesMemberships": False})
        return data["data"]["viewer"]["user_results"]["result"]

    def user(self, handle: str) -> dict:
        screen_name = handle.lstrip("@")
        data = self.gql("UserByScreenName", {"screen_name": screen_name, "withGrokTranslatedBio": False})
        result = (data.get("data", {}).get("user") or {}).get("result")
        if not result or result.get("__typename") != "User":
            reason = (result or {}).get("reason") or "not found"
            raise click.ClickException(f"@{screen_name}: {reason}")
        return result

    def timeline(self, name: str, variables: dict, path: list[str], limit: int,
                 since_id: str | None = None, page_size: int = PAGE_SIZE) -> list[dict]:
        """Page a timeline until `limit` tweets (0 = all), the end, or `since_id`."""
        out, seen, cursor = [], set(), None
        for _ in range(MAX_PAGES):
            v = dict(variables, count=page_size)
            if cursor:
                v["cursor"] = cursor
            data = self.gql(name, v)
            node = data
            for key in path:
                node = (node or {}).get(key) or {}
            tweets, cursor = parse_instructions(node.get("instructions") or [])
            fresh = 0
            for t in tweets:
                if since_id and t["id"] == since_id:
                    return out
                if t["id"] in seen:
                    continue
                seen.add(t["id"])
                out.append(t)
                fresh += 1
                if limit and len(out) >= limit:
                    return out
            log.debug("%s page: %d new, total %d", name, fresh, len(out))
            if not fresh or not cursor:
                return out
        raise click.ClickException(
            f"{name}: stopped after {MAX_PAGES} pages ({len(out)} tweets); pass a --limit or --since-id")


class SessionExpired(click.ClickException):
    """The saved session was rejected; a fresh browser session may work."""


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #
def iso_utc(created_at: str | None) -> str | None:
    """`Sun Nov 15 17:02:27 +0000 2026` -> `2026-11-15T17:02:27Z`."""
    if not created_at:
        return None
    try:
        dt = datetime.strptime(created_at, "%a %b %d %H:%M:%S %z %Y")
    except ValueError:
        return created_at
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_user(u: dict) -> dict:
    """A User result, old (`legacy`) or new (`core`/`*_counts`) schema."""
    legacy = u.get("legacy") or {}
    core = u.get("core") or {}
    counts = u.get("relationship_counts") or {}
    bio = (u.get("profile_bio") or {}).get("description")
    if bio is None:
        bio = legacy.get("description")
    bio_ents = ((u.get("profile_bio") or {}).get("entities") or legacy.get("entities") or {}).get("description") or {}
    for link in bio_ents.get("urls") or []:
        if bio and link.get("url") and link.get("expanded_url"):
            bio = bio.replace(link["url"], link["expanded_url"])
    return {
        "id": u.get("rest_id"),
        "handle": core.get("screen_name") or legacy.get("screen_name"),
        "name": core.get("name") or legacy.get("name"),
        "bio": bio,
        "location": (u.get("location") or {}).get("location") or legacy.get("location") or None,
        "created_at": iso_utc(core.get("created_at") or legacy.get("created_at")),
        "followers": counts.get("followers", legacy.get("followers_count")),
        "following": counts.get("following", legacy.get("friends_count")),
        "tweets": (u.get("tweet_counts") or {}).get("tweets", legacy.get("statuses_count")),
        "likes": (u.get("action_counts") or {}).get("favorites_count", legacy.get("favourites_count")),
        "verified": bool(u.get("is_blue_verified") or (u.get("verification") or {}).get("verified")),
        "protected": bool((u.get("privacy") or {}).get("protected", legacy.get("protected"))),
        "url": f"https://x.com/{core.get('screen_name') or legacy.get('screen_name')}",
    }


def _expand_urls(text: str, legacy: dict) -> str:
    """Replace t.co links with their targets and drop the trailing media link."""
    ents = legacy.get("entities") or {}
    for u in ents.get("urls") or []:
        if u.get("url") and u.get("expanded_url"):
            text = text.replace(u["url"], u["expanded_url"])
    for m in ents.get("media") or []:
        if m.get("url"):
            text = text.replace(m["url"], "")
    return text.strip()


def _media(legacy: dict) -> list[dict]:
    out = []
    for m in (legacy.get("extended_entities") or legacy.get("entities") or {}).get("media") or []:
        url = m.get("media_url_https")
        if m.get("type") in ("video", "animated_gif"):
            mp4s = [v for v in (m.get("video_info") or {}).get("variants") or [] if v.get("content_type") == "video/mp4"]
            if mp4s:
                url = max(mp4s, key=lambda v: v.get("bitrate") or 0)["url"]
        out.append({"type": m.get("type"), "url": url})
    return out


def norm_tweet(result: dict) -> dict | None:
    """A Tweet result to plain fields; None for tombstones and unavailable posts."""
    if not result:
        return None
    if result.get("__typename") == "TweetWithVisibilityResults":
        result = result.get("tweet") or {}
    if result.get("__typename") not in (None, "Tweet") or "legacy" not in result:
        return None
    legacy = result["legacy"]
    author = norm_user(((result.get("core") or {}).get("user_results") or {}).get("result") or {})
    note = ((result.get("note_tweet") or {}).get("note_tweet_results") or {}).get("result") or {}
    text = note.get("text") or legacy.get("full_text") or ""
    if not note:
        text = _expand_urls(text, legacy)
    else:
        for u in ((note.get("entity_set") or {}).get("urls")) or []:
            if u.get("url") and u.get("expanded_url"):
                text = text.replace(u["url"], u["expanded_url"])
    article = ((result.get("article") or {}).get("article_results") or {}).get("result")
    tid = result.get("rest_id") or legacy.get("id_str")
    views = (result.get("views") or {}).get("count")
    t = {
        "id": tid,
        "url": f"https://x.com/{author['handle']}/status/{tid}",
        "created_at": iso_utc(legacy.get("created_at")),
        "author": {k: author[k] for k in ("id", "handle", "name")},
        "text": text,
        "lang": legacy.get("lang"),
        "likes": legacy.get("favorite_count"),
        "retweets": legacy.get("retweet_count"),
        "replies": legacy.get("reply_count"),
        "quotes": legacy.get("quote_count"),
        "bookmarks": legacy.get("bookmark_count"),
        "views": int(views) if views and str(views).isdigit() else None,
        "conversation_id": legacy.get("conversation_id_str"),
        "in_reply_to": ({"id": legacy.get("in_reply_to_status_id_str"),
                         "handle": legacy.get("in_reply_to_screen_name")}
                        if legacy.get("in_reply_to_status_id_str") else None),
        "media": _media(legacy),
        "quoted": None,
        "retweeted": None,
    }
    if article:
        t["article"] = {"title": article.get("title"),
                        "text": article.get("plain_text") or article.get("preview_text")}
    rt = (legacy.get("retweeted_status_result") or {}).get("result")
    if rt:
        t["retweeted"] = norm_tweet(rt)
    qt = (result.get("quoted_status_result") or {}).get("result")
    if qt:
        t["quoted"] = norm_tweet(qt)
    return t


def _tweets_in(content: dict) -> list[dict]:
    """Tweets in one entry content: a single item or a module (conversation)."""
    out = []
    items = [content.get("itemContent")] if content.get("itemContent") else []
    items += [(i.get("item") or {}).get("itemContent") for i in content.get("items") or []]
    for ic in items:
        if ic and ic.get("__typename") == "TimelineTweet" and not ic.get("promotedMetadata"):
            t = norm_tweet((ic.get("tweet_results") or {}).get("result") or {})
            if t:
                out.append(t)
    return out


def parse_instructions(instructions: list[dict]) -> tuple[list[dict], str | None]:
    """(tweets in timeline order, bottom cursor) from timeline instructions."""
    tweets, cursor = [], None
    for ins in instructions:
        entries = ins.get("entries") or ([ins["entry"]] if ins.get("entry") else [])
        for e in entries:
            c = e.get("content") or {}
            if c.get("cursorType") == "Bottom" or e.get("entryId", "").startswith("cursor-bottom"):
                cursor = c.get("value") or cursor
                continue
            if e.get("entryId", "").startswith(("promoted-", "who-to-follow", "cursor-")):
                continue
            tweets.extend(_tweets_in(c))
    return tweets, cursor


def parse_tweet_id(arg: str) -> str:
    """A tweet id from an id or an x.com / twitter.com status URL."""
    m = re.search(r"(?:x|twitter)\.com/[^/]+/status(?:es)?/(\d+)", arg) or re.fullmatch(r"\s*(\d+)\s*", arg)
    if not m:
        raise click.BadParameter(f"{arg!r} is not a tweet id or URL, e.g. `x tweet https://x.com/jack/status/20`")
    return m.group(1)


def parse_handle(arg: str) -> str:
    """A handle from `@handle`, `handle` or a profile URL."""
    m = re.search(r"(?:x|twitter)\.com/@?([A-Za-z0-9_]{1,15})", arg) or re.fullmatch(r"\s*@?([A-Za-z0-9_]{1,15})\s*", arg)
    if not m:
        raise click.BadParameter(f"{arg!r} is not an X handle, e.g. `x user jack`")
    return m.group(1)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _flat(text: str) -> str:
    return re.sub(r"\s*\n\s*", " ↵ ", text or "").strip()


def fmt_tweet(t: dict) -> str:
    """One line: id, UTC time, @author, text (+ quote/media), counts, URL."""
    when = (t.get("created_at") or "")[:16].replace("T", " ")
    rt = t.get("retweeted")
    if rt:
        body = f"RT @{rt['author']['handle']}: {_flat(rt['text'])}"
    else:
        body = _flat(t["text"])
        if t.get("article"):
            body = f"[article] {t['article'].get('title') or ''} — {_flat(t['article'].get('text') or '')}".strip()
    if t.get("media"):
        kinds = sorted({m["type"] for m in t["media"]})
        body += f" [{len(t['media'])} {'/'.join(kinds)}]"
    q = t.get("quoted")
    if q:
        body += f" ⟪QT @{q['author']['handle']}: {_flat(q['text'])} {q['url']}⟫"
    c = rt or t  # a retweet's own counters are zero; show the original's
    counts = f"♥{c.get('likes') or 0} ↻{c.get('retweets') or 0} ↩{c.get('replies') or 0}"
    return f"{t['id']}\t{when} UTC\t@{t['author']['handle']}\t{body}\t{counts}\t{t['url']}"


def fmt_user(u: dict) -> str:
    flags = "".join(f for f, on in (("✓", u["verified"]), ("🔒", u["protected"])) if on)
    return (f"{u['id']}\t@{u['handle']}{flags}\t{u['name']}\t{u['followers']} followers\t"
            f"{u['following']} following\t{u['tweets']} posts\t{_flat(u.get('bio') or '')}\t{u['url']}")


def emit(rows: list[str], as_json: bool, data, raw=None, as_raw: bool = False) -> None:
    """stdout carries data only: text lines, normalized JSON, or the raw answer."""
    if as_raw:
        click.echo(jsonlib.dumps(raw, ensure_ascii=False))
    elif as_json:
        click.echo(jsonlib.dumps(data, ensure_ascii=False, indent=2))
    else:
        for r in rows:
            click.echo(r)


# --------------------------------------------------------------------------- #
# Session selection
# --------------------------------------------------------------------------- #
def _pick(sessions: list[dict], account: str | None, client_for) -> tuple[dict, dict]:
    """(session, viewer) for `account`, or the only account present."""
    found, errors = {}, []
    for sess in sessions:
        try:
            viewer = norm_user(client_for(sess).viewer())
        except click.ClickException as e:
            errors.append(f"{sess['browser']}/{sess['profile']}: {e.message}")
            continue
        found.setdefault(viewer["handle"].lower(), (sess, viewer))
    if account:
        hit = found.get(account.lstrip("@").lower())
        if hit:
            return hit
        raise click.ClickException(
            f"no signed-in browser session for @{account.lstrip('@')}; found: "
            f"{', '.join('@' + v['handle'] for _, v in found.values()) or 'none'}. Sign in at https://x.com first.")
    if len(found) == 1:
        return next(iter(found.values()))
    if not found:
        raise click.ClickException(NO_SESSION_MESSAGE + (f" ({'; '.join(errors)})" if errors else ""))
    raise click.ClickException(
        "several X accounts are signed in: "
        + ", ".join(f"@{v['handle']} ({s['browser']})" for s, v in found.values())
        + ". Pick one with `x --account <handle> …` or `x login --account <handle>`.")


class Ctx:
    """Lazily builds the client for the chosen account."""

    def __init__(self, account: str | None, use_cache: bool):
        self.account = account
        self.use_cache = use_cache
        self._x: X | None = None

    def client(self) -> X:
        if self._x:
            return self._x
        token, ct0 = env_value("X_AUTH_TOKEN"), env_value("X_CT0")
        if token and ct0:
            self._x = X(token, ct0, self.use_cache)
            return self._x
        cfg = load_config()
        wanted = (self.account or "").lstrip("@").lower()
        if cfg.get("auth_token") and (not wanted or cfg.get("handle", "").lower() == wanted):
            handle = cfg.get("handle")

            def refresh():
                log.info("saved X session expired; looking for a fresh @%s session in the browser", handle)
                try:
                    _, v = self.login(handle)
                except click.ClickException:
                    return None
                fresh = load_config()
                return fresh["auth_token"], fresh["ct0"]

            self._x = X(cfg["auth_token"], cfg["ct0"], self.use_cache, on_expired=refresh)
            return self._x
        self._x, _ = self.login(wanted or None)
        return self._x

    def login(self, account: str | None, source: str | None = None) -> tuple[X, dict]:
        sessions = browser_sessions(source)
        if not sessions:
            raise click.ClickException(NO_SESSION_MESSAGE)
        clients = {}

        def client_for(sess):
            clients[id(sess)] = X(sess["auth_token"], sess["ct0"], self.use_cache)
            return clients[id(sess)]

        sess, viewer = _pick(sessions, account, client_for)
        save_config({"auth_token": sess["auth_token"], "ct0": sess["ct0"], "user_id": viewer["id"],
                     "handle": viewer["handle"], "browser": sess["browser"], "profile": sess["profile"]})
        log.info("using @%s from %s/%s", viewer["handle"], sess["browser"], sess["profile"])
        return clients[id(sess)], viewer


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
JSON = click.option("--json", "as_json", is_flag=True, help="Normalized JSON on stdout.")
RAW = click.option("--raw", "as_raw", is_flag=True, help="The API's answer, untouched (debugging).")
LIMIT = click.option("--limit", "-n", default=20, show_default=True, help="Max tweets; 0 = all (paged).")
SINCE = click.option("--since-id", help="Stop when this tweet id is reached (exclusive): fetch only what is new.")


@click.group(context_settings={"help_option_names": ["-h", "--help"]},
             epilog="\b\nExamples:\n  x likes -n 10\n  x bookmarks --json\n  x search \"fhe\" -n 5\n  x thread https://x.com/jack/status/20")
@click.option("--account", help="X handle to act as when several are signed in (or $X_ACCOUNT).")
@click.option("--no-cache", is_flag=True, help="Re-scrape the x.com web bundle (query ids, flags).")
@click.option("--debug", is_flag=True, help="DEBUG logs on stderr.")
@click.pass_context
def cli(ctx, account, no_cache, debug):
    """Read X (Twitter) as yourself: likes, bookmarks, timelines, tweets, search."""
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO, format="%(message)s", stream=sys.stderr)
    logging.getLogger("urllib3").setLevel(logging.WARNING)  # its URLs carry kilobytes of feature flags
    ctx.obj = Ctx(account or env_value("X_ACCOUNT"), not no_cache)


# -- auth -------------------------------------------------------------------- #
@cli.command(epilog="\b\nExamples:\n  x login\n  x login --account jack --source arc")
@click.option("--source", type=click.Choice([s[0] for s in COOKIE_SOURCES]), help="Only read this browser.")
@click.pass_obj
def login(obj: Ctx, source):
    """Import the x.com session from a signed-in browser and save it."""
    _, v = obj.login(obj.account, source)
    click.echo(f"signed in as @{v['handle']} ({v['id']}); saved to {CONFIG_PATH}")


@cli.command(epilog="\b\nExamples:\n  x accounts\n  x accounts --json")
@JSON
@click.pass_obj
def accounts(obj: Ctx, as_json):
    """List the X sessions found in local browsers."""
    rows, data = [], []
    for sess in browser_sessions():
        try:
            v = norm_user(X(sess["auth_token"], sess["ct0"], obj.use_cache).viewer())
        except click.ClickException as e:
            v = {"handle": None, "id": sess["user_id"], "error": e.message}
        data.append({"browser": sess["browser"], "profile": sess["profile"], "handle": v["handle"],
                     "user_id": v["id"], **({"error": v["error"]} if "error" in v else {})})
    data.sort(key=lambda d: (d["browser"], d["profile"]))
    for d in data:
        rows.append(f"{d['browser']}\t{d['profile']}\t@{d['handle']}\t{d['user_id']}" + (f"\t{d['error']}" if d.get("error") else ""))
    emit(rows or ["(no x.com session in Chrome, Arc, Brave or Edge)"], as_json, data)


@cli.command(epilog="\b\nExamples:\n  x whoami\n  x whoami --json")
@JSON
@RAW
@click.pass_obj
def whoami(obj: Ctx, as_json, as_raw):
    """Show the signed-in account."""
    raw = obj.client().viewer()
    u = norm_user(raw)
    emit([fmt_user(u)], as_json, u, raw, as_raw)


@cli.command("auth-status", epilog="\b\nExamples:\n  x auth-status\n  x auth-status --json")
@JSON
def auth_status(as_json):
    """Where the saved session lives (no secrets)."""
    meta = auth_broker("status") or {"connector": "x", "source": "local" if CONFIG_PATH.exists() else "none",
                                     "pending": False, "last_sync": None}
    meta["local"] = CONFIG_PATH.exists()
    if CONFIG_PATH.with_suffix(".pending").exists():
        meta.update(source="pending", pending=True)
    click.echo(jsonlib.dumps(meta) if as_json else f"{meta['source']}; pending={meta['pending']}; local={meta['local']}")


@cli.command("auth-sync", epilog="\b\nExamples:\n  x auth-sync")
def auth_sync():
    """Push a locally saved session to the vault; exits 3 while still pending."""
    if not CONFIG_PATH.exists():
        raise click.ClickException("no local session to synchronize; run `x login` first")
    meta = auth_broker("save", jsonlib.loads(CONFIG_PATH.read_text()))
    if not meta:
        raise click.ClickException("vault broker `claudine-secret` unavailable; the local session is kept")
    if meta.get("source") == "vault" and not meta.get("pending"):
        CONFIG_PATH.with_suffix(".pending").unlink(missing_ok=True)
    click.echo(jsonlib.dumps(meta))
    if meta.get("pending"):
        raise click.exceptions.Exit(3)


# -- reads ------------------------------------------------------------------- #
def _viewer_id(x: X) -> str:
    cfg_uid = load_config().get("user_id") if not env_value("X_AUTH_TOKEN") else None
    return cfg_uid or x.viewer()["rest_id"]


@cli.command(epilog="\b\nExamples:\n  x likes\n  x likes -n 100 --json\n  x likes -n 0 --json > likes.json\n  x likes --since-id 1234567890123456789")
@LIMIT
@SINCE
@JSON
@click.pass_obj
def likes(obj: Ctx, limit, since_id, as_json):
    """Your liked posts, most recently liked first (X hides other people's likes)."""
    x = obj.client()
    tweets = x.timeline("Likes", {"userId": _viewer_id(x), "includePromotedContent": False,
                                  "withClientEventToken": False, "withBirdwatchNotes": False, "withVoice": True},
                        ["data", "user", "result", "timeline", "timeline"], limit, since_id)
    emit([fmt_tweet(t) for t in tweets] or ["(no likes)"], as_json, tweets)


def _folders(x: X) -> list[dict]:
    data = x.gql("BookmarkFoldersSlice", {})
    items = (((data.get("data") or {}).get("viewer") or {}).get("user_results") or {}).get("result", {})
    items = ((items.get("bookmark_collections_slice") or {}).get("items")) or []
    return [{"id": f.get("id"), "name": f.get("name")} for f in items]


def _resolve_folder(x: X, arg: str) -> dict:
    folders = _folders(x)
    exact = [f for f in folders if arg in (f["id"], f["name"]) or f["name"].lower() == arg.lower()]
    hits = exact or [f for f in folders if arg.lower() in f["name"].lower()]
    if len(hits) == 1:
        return hits[0]
    names = ", ".join(f"{f['name']} ({f['id']})" for f in folders) or "none"
    raise click.ClickException(f"{'ambiguous' if hits else 'no'} bookmark folder {arg!r}; folders: {names}")


@cli.command(epilog="\b\nExamples:\n  x bookmarks\n  x bookmarks -n 0 --json > bookmarks.json\n  x bookmarks --folder reading")
@click.option("--folder", help="A bookmark folder name or id (see `x bookmark-folders`).")
@LIMIT
@SINCE
@JSON
@click.pass_obj
def bookmarks(obj: Ctx, folder, limit, since_id, as_json):
    """Your bookmarked posts, most recently bookmarked first."""
    x = obj.client()
    if folder:
        f = _resolve_folder(x, folder)
        tweets = x.timeline("BookmarkFolderTimeline", {"bookmark_collection_id": f["id"], "includePromotedContent": False},
                            ["data", "bookmark_collection_timeline", "timeline"], limit, since_id)
    else:
        tweets = x.timeline("Bookmarks", {"includePromotedContent": False},
                            ["data", "bookmark_timeline_v2", "timeline"], limit, since_id)
    emit([fmt_tweet(t) for t in tweets] or ["(no bookmarks)"], as_json, tweets)


@cli.command("bookmark-folders", epilog="\b\nExamples:\n  x bookmark-folders\n  x bookmark-folders --json")
@JSON
@click.pass_obj
def bookmark_folders(obj: Ctx, as_json):
    """Your bookmark folders (X Premium)."""
    folders = _folders(obj.client())
    emit([f"{f['id']}\t{f['name']}" for f in folders] or ["(no bookmark folders)"], as_json, folders)


@cli.command(epilog="\b\nExamples:\n  x tweet 20\n  x tweet https://x.com/jack/status/20 21 --json")
@click.argument("tweets", nargs=-1, required=True)
@JSON
@RAW
@click.pass_obj
def tweet(obj: Ctx, tweets, as_json, as_raw):
    """One or more posts by id or URL."""
    x = obj.client()
    ids = [parse_tweet_id(a) for a in tweets]
    out, raws = [], []
    for tid in ids:
        data = x.gql("TweetResultByRestId", {"tweetId": tid, "withCommunity": False,
                                             "includePromotedContent": False, "withVoice": False})
        raws.append(data)
        result = ((data.get("data") or {}).get("tweetResult") or {}).get("result") or {}
        t = norm_tweet(result)
        if t is None:
            reason = result.get("reason") or (result.get("tombstone") or {}).get("text", {}).get("text") or "unavailable"
            log.warning("%s: %s", tid, reason)
            continue
        out.append(t)
    if not out:
        raise click.ClickException(f"no post available among {', '.join(ids)}")
    emit([fmt_tweet(t) for t in out], as_json, out, raws, as_raw)


@cli.command(epilog="\b\nExamples:\n  x thread https://x.com/jack/status/20\n  x thread 20 --replies --json")
@click.argument("tweet_ref")
@click.option("--replies", is_flag=True, help="Also list the replies X loads on the first page.")
@JSON
@RAW
@click.pass_obj
def thread(obj: Ctx, tweet_ref, replies, as_json, as_raw):
    """A post with its parents and the author's own thread (and replies on demand)."""
    x = obj.client()
    tid = parse_tweet_id(tweet_ref)
    data = x.gql("TweetDetail", {
        "focalTweetId": tid, "with_rux_injections": False, "rankingMode": "Relevance",
        "includePromotedContent": False, "withCommunity": True, "withQuickPromoteEligibilityTweetFields": False,
        "withBirdwatchNotes": True, "withVoice": True})
    ins = ((data.get("data") or {}).get("threaded_conversation_with_injections_v2") or {}).get("instructions") or []
    tweets, _ = parse_instructions(ins)
    focal = next((t for t in tweets if t["id"] == tid), None)
    if focal is None:
        raise click.ClickException(f"post {tid} is unavailable (deleted, protected or not found)")
    idx = tweets.index(focal)
    chain = tweets[: idx + 1]
    # The author's continuation: following replies by the same author chained to the previous post.
    last = focal
    for t in tweets[idx + 1:]:
        if t["author"]["id"] == focal["author"]["id"] and (t.get("in_reply_to") or {}).get("id") == last["id"]:
            chain.append(t)
            last = t
    rest = [t for t in tweets[idx + 1:] if t not in chain] if replies else []
    out = {"thread": chain, "replies": rest} if replies else chain
    rows = [fmt_tweet(t) for t in chain] + (["-- replies --"] + [fmt_tweet(t) for t in rest] if rest else [])
    emit(rows, as_json, out, data, as_raw)


@cli.command(epilog="\b\nExamples:\n  x user jack\n  x user @jack https://x.com/elonmusk --json")
@click.argument("handles", nargs=-1, required=True)
@JSON
@RAW
@click.pass_obj
def user(obj: Ctx, handles, as_json, as_raw):
    """One or more profiles by handle or URL."""
    x = obj.client()
    raws = [x.user(parse_handle(h)) for h in handles]
    users = [norm_user(r) for r in raws]
    emit([fmt_user(u) for u in users], as_json, users, raws, as_raw)


@cli.command(epilog="\b\nExamples:\n  x tweets jack -n 10\n  x tweets @jack --replies --json")
@click.argument("handle")
@click.option("--replies", is_flag=True, help="Include the user's replies.")
@LIMIT
@SINCE
@JSON
@click.pass_obj
def tweets(obj: Ctx, handle, replies, limit, since_id, as_json):
    """A user's posts, newest first (pinned post first when X puts it there)."""
    x = obj.client()
    uid = x.user(parse_handle(handle))["rest_id"]
    name = "UserTweetsAndReplies" if replies else "UserTweets"
    out = x.timeline(name, {"userId": uid, "includePromotedContent": False, "withCommunity": True,
                            "withQuickPromoteEligibilityTweetFields": False, "withVoice": True},
                     ["data", "user", "result", "timeline", "timeline"], limit, since_id)
    if not replies:
        out = [t for t in out if t["author"]["id"] == uid or t.get("retweeted")]
    emit([fmt_tweet(t) for t in out] or ["(no posts)"], as_json, out)


@cli.command(epilog="\b\nExamples:\n  x home\n  x home --following -n 50 --json")
@click.option("--following", is_flag=True, help="The chronological Following feed instead of For You.")
@LIMIT
@JSON
@click.pass_obj
def home(obj: Ctx, following, limit, as_json):
    """Your home timeline (For You, or Following)."""
    x = obj.client()
    name = "HomeLatestTimeline" if following else "HomeTimeline"
    out = x.timeline(name, {"includePromotedContent": False, "latestControlAvailable": True,
                            "requestContext": "launch", "withCommunity": True},
                     ["data", "home", "home_timeline_urt"], limit)
    emit([fmt_tweet(t) for t in out] or ["(empty timeline)"], as_json, out)


@cli.command(epilog="\b\nExamples:\n  x search \"fhe\"\n  x search \"from:jack since:2024-01-01\" --top -n 50 --json")
@click.argument("query")
@click.option("--top", is_flag=True, help="Top results instead of Latest.")
@LIMIT
@JSON
@click.pass_obj
def search(obj: Ctx, query, top, limit, as_json):
    """Search posts; takes X's operators (from:, to:, since:, until:, filter:, lang:, min_faves:)."""
    x = obj.client()
    out = x.timeline("SearchTimeline", {"rawQuery": query, "querySource": "typed_query",
                                        "product": "Top" if top else "Latest"},
                     ["data", "search_by_raw_query", "search_timeline", "timeline"], limit)
    emit([fmt_tweet(t) for t in out] or ["(no results)"], as_json, out)


def main():
    try:
        cli(standalone_mode=True)
    except requests.RequestException as e:
        logging.getLogger("x-cli").error("network error: %s — check the connection and retry", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
