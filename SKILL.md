---
name: x-cli
description: >
  Read X (Twitter) as the signed-in user from the terminal with the `x` command:
  your liked posts, your bookmarks (and bookmark folders), single posts and
  whole threads by URL, user profiles, a user's posts, your home timeline (For
  You or Following), and search with X's operators. Read-only: it never posts,
  likes or follows. Talks to the private GraphQL API of the x.com web app with
  the session of a signed-in Chrome/Arc/Brave/Edge, so there is nothing to
  paste. Every read supports --json. Triggers: "my x likes", "my twitter
  bookmarks", "what did I bookmark on x", "read this tweet", "read this x
  thread", "search x for", "what is @someone posting", "x cli", "twitter cli".
---

# X CLI

`x` reads X with the account signed in to a local browser. It uses the same
GraphQL endpoints as x.com, so it sees what you see there: your likes,
bookmarks, home feed, search, any public profile or post.

## How to invoke

Run **`x`**, on `$PATH` through `claudine/scripts/link_clis.py`, which links
this repo's `bin/x` into `~/.local/bin`; otherwise run `<skill-dir>/bin/x`. It
is a PEP 723 `uv` script, so dependencies resolve on the first run.

## Authentication

None to set up when you are signed in to x.com in Chrome, Arc, Brave or Edge:
the `auth_token` and `ct0` cookies are decrypted from the browser's cookie store
with the macOS keychain key (macOS may ask once to allow "Chrome Safe Storage":
Always Allow).

```bash
x accounts                       # every x.com session found in local browsers
x login                          # import the session and save it (~/.config/x-cli/config.json, chmod 600)
x login --account <handle>       # when several accounts are signed in
x --account <handle> likes       # act as one account for one call (or X_ACCOUNT=<handle>)
x whoami                         # which account the CLI is using
x auth-status --json             # where the saved session lives, no secrets
```

- The first read without a saved session imports the browser's one by itself;
  when several accounts are signed in, it fails and lists them: pass
  `--account`.
- A rejected saved session is replaced once by the browser's current session
  for the same handle.
- `X_AUTH_TOKEN` + `X_CT0` override everything (both needed).

## Output conventions

- Default: one line per post, tab-separated:
  `id  YYYY-MM-DD HH:MM UTC  @author  text  ♥likes ↻retweets ↩replies  url`.
  Newlines in the text become ` ↵ `; a quote is inlined as `⟪QT @x: … url⟫`,
  media as `[2 photo]`, a retweet as `RT @x: …` with the original's counts.
- `--json`: normalized posts: `id, url, created_at (UTC ISO), author {id,
  handle, name}, text (t.co links expanded, long posts in full), lang, likes,
  retweets, replies, quotes, bookmarks, views, conversation_id, in_reply_to,
  media [{type, url (best mp4 for videos)}], quoted, retweeted, article?`.
- `--raw` (single-record commands): the GraphQL answer untouched.
- stdout is data only; logs and warnings go to stderr (`--debug` for more).

## Commands

```bash
# Your account
x likes                               # 20 most recently liked posts
x likes -n 200 --json                 # more; -n 0 = all (paged by 20)
x likes --since-id <tweet_id>         # only what was liked after that post
x bookmarks                           # most recently bookmarked first
x bookmarks -n 0 --json > bookmarks.json
x bookmark-folders                    # Premium folders: id + name
x bookmarks --folder <name|id>        # one folder
x home                                # For You
x home --following -n 50              # chronological Following feed

# Posts and people
x tweet <id|url> [<id|url> ...]       # one or many posts
x thread <id|url>                     # parents + the post + the author's own continuation
x thread <id|url> --replies --json    # plus the replies of the first page
x user <handle|url> [...]             # profiles: followers, following, posts, likes, bio
x tweets <handle> -n 20               # a user's posts (and retweets); --replies to include replies
x search "<query>" -n 50              # Latest; --top for Top
x search "from:<handle> since:2026-01-01 min_faves:10"

# Session
x accounts | x login | x whoami | x auth-status | x auth-sync
```

There are no write commands, by design.

## Recipes

```bash
# Everything I liked this week (likes are ordered by like time, not post time)
x likes -n 100 --json | jq '.[] | select(.created_at > "2026-11-09") | {url, text}'

# Export all bookmarks once, then filter the file instead of re-fetching
x bookmarks -n 0 --json > ~/Downloads/x/bookmarks.json
jq -r '.[] | select(.text | test("fhe"; "i")) | .url' ~/Downloads/x/bookmarks.json

# Incremental sync: remember the newest id, fetch only what is new next time
NEWEST=$(jq -r '.[0].id' likes.json); x likes -n 0 --since-id "$NEWEST" --json

# Read a thread someone sent as a link
x thread https://x.com/<handle>/status/<id>

# All links from my bookmarks
x bookmarks -n 0 --json | jq -r '.[].text' | grep -oE 'https?://[^ ]+' | sort -u
```

## Gotchas

- **Likes are your own only.** X made likes private in 2024; there is no
  command for someone else's.
- **Query ids rotate** with every x.com deploy. They are scraped from the web
  bundle (`main.js` plus the lazy `Bookmarks`/`HomeTimeline` chunks) and cached
  6 h in `~/.cache/x-cli/web.json`; a 404 re-scrapes once. `--no-cache` forces
  it. Measured: 1.4 s cold, 0.8 s warm for a 20-post read.
- **`x-client-transaction-id`** is sent on every call: `SearchTimeline` answers
  404 without it. It is computed locally (XClientTransaction library) from the
  cached home page.
- **Rate limits per 15 min** (from `x-rate-limit-limit`, measured): Likes 500,
  Viewer 100, UserTweets 50. A 429 that resets within 90 s is waited out;
  otherwise the error gives the reset time. `-n 0` on 3600 likes is ~180 calls,
  well inside the Likes budget.
- **`home`** ignores the requested page size (one page holds ~80 posts); `-n`
  is applied client-side. Promoted posts are dropped everywhere.
- **Thread** reads one `TweetDetail` page: very long reply trees are not
  paged. The author's continuation is the chain of the author's own replies to
  the previous post.
- **Bookmark folders** exist only for X Premium accounts; `--folder` was not
  exercised live (the test account has no folders).
- X's user schema moved fields out of `legacy` in 2026 (`core.screen_name`,
  `relationship_counts`, `action_counts`); the normalizer reads both.
