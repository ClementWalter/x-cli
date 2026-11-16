# x-cli

**Visibility: public.**

Read X (Twitter) from the terminal as yourself: your likes, bookmarks and home
timeline, posts and threads by URL, profiles, a user's posts, and search.
Read-only: it never posts, likes or follows.

Single-file Python CLI (`x_cli.py`, PEP 723, run with `uv`). It talks to the
private GraphQL API of the x.com web app with the session of a signed-in
Chromium browser (Chrome, Arc, Brave, Edge), decrypted from its cookie store
with the macOS keychain key, so there is nothing to paste.

## Install

```bash
uv run claudine/scripts/link_clis.py   # put `x` on $PATH
x accounts                             # sessions found in local browsers
x login                                # optional: save one (--account <handle> if several)
```

## Usage

```bash
x likes -n 20                          # your latest likes
x bookmarks -n 0 --json > bm.json      # every bookmark
x thread https://x.com/jack/status/20  # a post and its thread
x user jack                            # a profile
x tweets jack --replies                # a user's posts
x home --following                     # chronological feed
x search "from:jack since:2024-01-01" --top
```

Every read takes `--json`; lists take `--limit/-n` (0 = all) and the account
timelines `--since-id` for incremental pulls. See [SKILL.md](SKILL.md) for the
full reference, output format and measured limits.

## How it works

- **Session**: `auth_token` + `ct0` cookies from the browser
  (`X_AUTH_TOKEN`/`X_CT0` override), saved chmod 600 in
  `~/.config/x-cli/config.json` and, when the `claudine-secret` broker is
  installed, synced to the vault.
- **Query ids and feature flags** are scraped from the x.com web bundle and
  cached for 6 h in `~/.cache/x-cli/`.
- **`x-client-transaction-id`** is generated locally with
  [XClientTransaction](https://github.com/iSarabjitDhiman/XClientTransaction).

## Tests

```bash
uv run --script tests/test_x_cli.py
```

## Privacy Policy

The Claude Desktop extension built from this repository keeps your data on your
Mac and talks only to the service it connects to. Full policy:
<https://clementwalter.github.io/claude-extensions/privacy/>
