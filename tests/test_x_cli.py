#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pytest==9.1.1",
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
"""Offline tests for x_cli: parsing, normalization, paging and the CLI surface.

GraphQL answers are synthetic, shaped like the x.com web API's, with fake ids.
The network seam is `X.gql`, replaced by a stub that serves them by operation.
"""

import hashlib
import hmac
import importlib.util
import json
import sys
from pathlib import Path

import click
import pytest
from click.testing import CliRunner
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

_spec = importlib.util.spec_from_file_location("x_cli", Path(__file__).resolve().parent.parent / "x_cli.py")
x_cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(x_cli)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
def user_result(uid="1234", handle="someone", schema="new"):
    if schema == "legacy":
        return {"__typename": "User", "rest_id": uid, "is_blue_verified": False,
                "legacy": {"screen_name": handle, "name": "Some One", "description": "bio https://t.co/abc",
                           "entities": {"description": {"urls": [{"url": "https://t.co/abc",
                                                                  "expanded_url": "https://example.com"}]}},
                           "followers_count": 10, "friends_count": 5, "statuses_count": 7,
                           "favourites_count": 3, "created_at": "Mon May 17 06:23:48 +0000 2010"}}
    return {"__typename": "User", "rest_id": uid, "is_blue_verified": True,
            "core": {"screen_name": handle, "name": "Some One", "created_at": "Mon May 17 06:23:48 +0000 2010"},
            "profile_bio": {"description": "bio"}, "relationship_counts": {"followers": 10, "following": 5},
            "tweet_counts": {"tweets": 7}, "action_counts": {"favorites_count": 3},
            "privacy": {"protected": False}, "location": {"location": "Nowhere"}}


def tweet_result(tid="1000", text="hello https://t.co/x1", author="1234", handle="someone", **extra):
    legacy = {"id_str": tid, "full_text": text, "created_at": "Sun Nov 15 17:02:27 +0000 2026",
              "favorite_count": 5, "retweet_count": 2, "reply_count": 1, "quote_count": 0,
              "bookmark_count": 0, "lang": "en", "conversation_id_str": tid,
              "entities": {"urls": [{"url": "https://t.co/x1", "expanded_url": "https://example.com/a"}]}}
    legacy.update(extra.pop("legacy", {}))
    return {"__typename": "Tweet", "rest_id": tid, "legacy": legacy, "views": {"count": "42"},
            "core": {"user_results": {"result": user_result(author, handle)}}, **extra}


def entry(t):
    return {"entryId": f"tweet-{t['rest_id']}", "content": {"__typename": "TimelineTimelineItem", "itemContent": {
        "__typename": "TimelineTweet", "tweet_results": {"result": t}}}}


def page(tweets, cursor="c-next"):
    entries = [entry(t) for t in tweets]
    if cursor:
        entries.append({"entryId": "cursor-bottom-1", "content": {"cursorType": "Bottom", "value": cursor}})
    return [{"type": "TimelineAddEntries", "entries": entries}]


def likes_answer(instructions):
    return {"data": {"user": {"result": {"timeline": {"timeline": {"instructions": instructions}}}}}}


class StubX(x_cli.X):
    """An X whose `gql` serves canned answers per operation, in call order."""

    def __init__(self, answers):
        self.answers = {k: list(v) for k, v in answers.items()}
        self.calls = []

    def gql(self, name, variables, _retry=True):
        self.calls.append((name, variables))
        return self.answers[name].pop(0)


@pytest.fixture
def run(monkeypatch, tmp_path):
    """Invoke the CLI against a StubX, with config isolated in tmp_path."""
    monkeypatch.setattr(x_cli, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setenv("X_AUTH_TOKEN", "")

    def _run(args, answers):
        stub = StubX(answers)
        monkeypatch.setattr(x_cli.Ctx, "client", lambda self: stub)
        return CliRunner().invoke(x_cli.cli, args)

    return _run


VIEWER = {"data": {"viewer": {"user_results": {"result": user_result("1234", "someone")}}}}


# --------------------------------------------------------------------------- #
# Cookies
# --------------------------------------------------------------------------- #
def _encrypt(value: bytes) -> bytes:
    key = PBKDF2(b"secret", b"saltysalt", 16, count=1003, prf=lambda p, s: hmac.new(p, s, hashlib.sha1).digest())
    pad = 16 - len(value) % 16
    return b"v10" + AES.new(key, AES.MODE_CBC, iv=b" " * 16).encrypt(value + bytes([pad]) * pad), key


def test_decrypt_cookie_plain():
    enc, key = _encrypt(b"token123")
    assert x_cli.decrypt_cookie(enc, key) == "token123"


def test_decrypt_cookie_with_domain_hash_prefix():
    enc, key = _encrypt(hashlib.sha256(b".x.com").digest() + b"token123")
    assert x_cli.decrypt_cookie(enc, key) == "token123"


def test_decrypt_cookie_rejects_unencrypted():
    assert x_cli.decrypt_cookie(b"plain", b"0" * 16) is None


@pytest.mark.parametrize("twid,expected", [("u%3D1234", "1234"), ('"u=1234"', "1234"), ("garbage", None)])
def test_uid_from_twid(twid, expected):
    assert x_cli.uid_from_twid(twid) == expected


# --------------------------------------------------------------------------- #
# Web bundle parsing
# --------------------------------------------------------------------------- #
BUNDLE = ('e.exports={queryId:"AbC-1",operationName:"Likes",operationType:"query",'
          'metadata:{featureSwitches:["f_one","f_two"],fieldToggles:["withArticlePlainText"]}};'
          'e.exports={queryId:"DeF_2",operationName:"Viewer",operationType:"query",metadata:{featureSwitches:[]}}')


def test_parse_operations_query_id():
    assert x_cli.parse_operations(BUNDLE)["Likes"]["query_id"] == "AbC-1"


def test_parse_operations_features():
    assert x_cli.parse_operations(BUNDLE)["Likes"]["features"] == ["f_one", "f_two"]


def test_parse_operations_toggles():
    assert x_cli.parse_operations(BUNDLE)["Likes"]["toggles"] == ["withArticlePlainText"]


def test_parse_operations_without_toggles():
    assert x_cli.parse_operations(BUNDLE)["Viewer"]["toggles"] == []


def test_parse_switches():
    html = '{"f_one":{"value":true},"f_two":{"value":false}}'
    assert x_cli.parse_switches(html) == {"f_one": True, "f_two": False}


def test_chunk_urls_builds_hashed_name():
    html = '{12:"shared~bundle.Bookmarks",13:"bundle.Home"}[...]{12:"0123456789abcdef",13:"fedcba9876543210"}'
    assert x_cli.chunk_urls(html, "Bookmark") == [f"{x_cli.ASSETS}/shared~bundle.Bookmarks.0123456789abcdefa.js"]


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("arg", ["20", "https://x.com/jack/status/20", "https://twitter.com/jack/status/20?s=1",
                                 "https://x.com/jack/status/20/photo/1"])
def test_parse_tweet_id(arg):
    assert x_cli.parse_tweet_id(arg) == "20"


def test_parse_tweet_id_rejects_text():
    with pytest.raises(click.BadParameter):
        x_cli.parse_tweet_id("not a tweet")


@pytest.mark.parametrize("arg", ["jack", "@jack", "https://x.com/jack", "https://twitter.com/jack/likes"])
def test_parse_handle(arg):
    assert x_cli.parse_handle(arg) == "jack"


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #
def test_iso_utc():
    assert x_cli.iso_utc("Sun Nov 15 17:02:27 +0000 2026") == "2026-11-15T17:02:27Z"


@pytest.mark.parametrize("schema", ["new", "legacy"])
def test_norm_user_handle_across_schemas(schema):
    assert x_cli.norm_user(user_result(schema=schema))["handle"] == "someone"


@pytest.mark.parametrize("schema", ["new", "legacy"])
def test_norm_user_followers_across_schemas(schema):
    assert x_cli.norm_user(user_result(schema=schema))["followers"] == 10


def test_norm_user_expands_bio_links():
    assert x_cli.norm_user(user_result(schema="legacy"))["bio"] == "bio https://example.com"


def test_norm_tweet_expands_tco():
    assert x_cli.norm_tweet(tweet_result())["text"] == "hello https://example.com/a"


def test_norm_tweet_url():
    assert x_cli.norm_tweet(tweet_result())["url"] == "https://x.com/someone/status/1000"


def test_norm_tweet_views_as_int():
    assert x_cli.norm_tweet(tweet_result())["views"] == 42


def test_norm_tweet_prefers_note_text():
    t = tweet_result(note_tweet={"note_tweet_results": {"result": {"text": "long form"}}})
    assert x_cli.norm_tweet(t)["text"] == "long form"


def test_norm_tweet_unwraps_visibility_results():
    wrapped = {"__typename": "TweetWithVisibilityResults", "tweet": tweet_result(tid="1001")}
    assert x_cli.norm_tweet(wrapped)["id"] == "1001"


def test_norm_tweet_tombstone_is_none():
    assert x_cli.norm_tweet({"__typename": "TweetTombstone"}) is None


def test_norm_tweet_quoted():
    t = tweet_result(quoted_status_result={"result": tweet_result(tid="2000", handle="other")})
    assert x_cli.norm_tweet(t)["quoted"]["author"]["handle"] == "other"


def test_norm_tweet_retweet():
    t = tweet_result(legacy={"retweeted_status_result": {"result": tweet_result(tid="3000")}})
    assert x_cli.norm_tweet(t)["retweeted"]["id"] == "3000"


def test_norm_tweet_picks_best_mp4():
    media = [{"type": "video", "url": "https://t.co/m", "media_url_https": "https://pbs.example.com/thumb.jpg",
              "video_info": {"variants": [
                  {"content_type": "application/x-mpegURL", "url": "https://video.example.com/p.m3u8"},
                  {"content_type": "video/mp4", "bitrate": 100, "url": "https://video.example.com/low.mp4"},
                  {"content_type": "video/mp4", "bitrate": 900, "url": "https://video.example.com/high.mp4"}]}}]
    t = tweet_result(legacy={"extended_entities": {"media": media}})
    assert x_cli.norm_tweet(t)["media"] == [{"type": "video", "url": "https://video.example.com/high.mp4"}]


def test_parse_instructions_cursor():
    assert x_cli.parse_instructions(page([tweet_result()], cursor="abc"))[1] == "abc"


def test_parse_instructions_skips_promoted():
    ins = page([tweet_result()])
    ins[0]["entries"].insert(0, {"entryId": "promoted-tweet-9", "content": entry(tweet_result("9"))["content"]})
    assert [t["id"] for t in x_cli.parse_instructions(ins)[0]] == ["1000"]


def test_parse_instructions_reads_modules():
    module = {"entryId": "conversationthread-1", "content": {"__typename": "TimelineTimelineModule", "items": [
        {"item": {"itemContent": {"__typename": "TimelineTweet", "tweet_results": {"result": tweet_result("5")}}}},
        {"item": {"itemContent": {"__typename": "TimelineTweet", "tweet_results": {"result": tweet_result("6")}}}}]}}
    ins = [{"type": "TimelineAddEntries", "entries": [module]}]
    assert [t["id"] for t in x_cli.parse_instructions(ins)[0]] == ["5", "6"]


def test_fmt_tweet_retweet_shows_original_counts():
    rt = tweet_result(legacy={"retweeted_status_result": {"result": tweet_result(tid="3000")},
                              "favorite_count": 0})
    assert "♥5 " in x_cli.fmt_tweet(x_cli.norm_tweet(rt))


def test_fmt_tweet_is_one_line():
    assert "\n" not in x_cli.fmt_tweet(x_cli.norm_tweet(tweet_result(text="a\nb")))


# --------------------------------------------------------------------------- #
# Paging
# --------------------------------------------------------------------------- #
PATH = ["data", "user", "result", "timeline", "timeline"]


def test_timeline_follows_cursor():
    x = StubX({"Likes": [likes_answer(page([tweet_result("1")])), likes_answer(page([tweet_result("2")], None))]})
    assert [t["id"] for t in x.timeline("Likes", {}, PATH, 0)] == ["1", "2"]


def test_timeline_stops_at_limit():
    x = StubX({"Likes": [likes_answer(page([tweet_result("1"), tweet_result("2")]))]})
    assert len(x.timeline("Likes", {}, PATH, 1)) == 1


def test_timeline_stops_at_since_id():
    x = StubX({"Likes": [likes_answer(page([tweet_result("3"), tweet_result("2"), tweet_result("1")]))]})
    assert [t["id"] for t in x.timeline("Likes", {}, PATH, 0, since_id="2")] == ["3"]


def test_timeline_stops_on_page_without_new_tweets():
    x = StubX({"Likes": [likes_answer(page([tweet_result("1")])), likes_answer(page([tweet_result("1")]))]})
    assert [t["id"] for t in x.timeline("Likes", {}, PATH, 0)] == ["1"]


def test_timeline_page_cap_fails_loudly(monkeypatch):
    monkeypatch.setattr(x_cli, "MAX_PAGES", 2)
    x = StubX({"Likes": [likes_answer(page([tweet_result("1")])), likes_answer(page([tweet_result("2")]))]})
    with pytest.raises(click.ClickException, match="stopped after 2 pages"):
        x.timeline("Likes", {}, PATH, 0)


def test_timeline_sends_cursor():
    x = StubX({"Likes": [likes_answer(page([tweet_result("1")], "next")), likes_answer(page([], None))]})
    x.timeline("Likes", {}, PATH, 0)
    assert x.calls[1][1]["cursor"] == "next"


# --------------------------------------------------------------------------- #
# Account selection
# --------------------------------------------------------------------------- #
SESSIONS = [{"browser": "chrome", "profile": "Default", "auth_token": "a", "ct0": "c"},
            {"browser": "arc", "profile": "Default", "auth_token": "b", "ct0": "d"}]


class ViewerStub:
    """A client whose only call is `viewer`."""

    def __init__(self, handle):
        self.handle = handle

    def viewer(self):
        return user_result(handle=self.handle)


def _client_for(sess):
    return ViewerStub({"a": "first", "b": "second"}[sess["auth_token"]])


def test_pick_ambiguous_lists_accounts():
    with pytest.raises(click.ClickException, match="@first .*@second"):
        x_cli._pick(SESSIONS, None, _client_for)


def test_pick_by_account():
    assert x_cli._pick(SESSIONS, "@Second", _client_for)[0]["browser"] == "arc"


def test_pick_unknown_account_names_found():
    with pytest.raises(click.ClickException, match="found: @first, @second"):
        x_cli._pick(SESSIONS, "nobody", _client_for)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_likes_json(run):
    out = run(["likes", "--json"], {"Viewer": [VIEWER], "Likes": [likes_answer(page([tweet_result()], None))]})
    assert json.loads(out.output)[0]["id"] == "1000"


def test_likes_text_line(run):
    out = run(["likes"], {"Viewer": [VIEWER], "Likes": [likes_answer(page([tweet_result()], None))]})
    assert out.output.startswith("1000\t2026-11-15 17:02 UTC\t@someone\t")


def test_bookmarks_json(run):
    ans = {"data": {"bookmark_timeline_v2": {"timeline": {"instructions": page([tweet_result()], None)}}}}
    out = run(["bookmarks", "--json"], {"Bookmarks": [ans]})
    assert json.loads(out.output)[0]["text"] == "hello https://example.com/a"


def test_bookmark_folder_unknown_lists_folders(run):
    folders = {"data": {"viewer": {"user_results": {"result": {"bookmark_collections_slice": {
        "items": [{"id": "77", "name": "reading"}]}}}}}}
    out = run(["bookmarks", "--folder", "nope"], {"BookmarkFoldersSlice": [folders]})
    assert "folders: reading (77)" in out.output


def test_tweet_json(run):
    ans = {"data": {"tweetResult": {"result": tweet_result()}}}
    out = run(["tweet", "https://x.com/someone/status/1000", "--json"], {"TweetResultByRestId": [ans]})
    assert json.loads(out.output)[0]["author"]["handle"] == "someone"


def test_tweet_unavailable_fails(run):
    ans = {"data": {"tweetResult": {"result": {"__typename": "TweetUnavailable", "reason": "Suspended"}}}}
    out = run(["tweet", "1000"], {"TweetResultByRestId": [ans]})
    assert out.exit_code == 1


def test_user_json(run):
    ans = {"data": {"user": {"result": user_result()}}}
    out = run(["user", "@someone", "--json"], {"UserByScreenName": [ans]})
    assert json.loads(out.output)[0]["likes"] == 3


def test_search_json(run):
    ans = {"data": {"search_by_raw_query": {"search_timeline": {"timeline": {
        "instructions": page([tweet_result()], None)}}}}}
    out = run(["search", "hello", "--json"], {"SearchTimeline": [ans]})
    assert json.loads(out.output)[0]["id"] == "1000"


def test_thread_keeps_author_chain_only(run):
    tweets = [tweet_result("1"),
              tweet_result("2", legacy={"in_reply_to_status_id_str": "1"}),
              tweet_result("3", author="9999", handle="other", legacy={"in_reply_to_status_id_str": "1"})]
    ans = {"data": {"threaded_conversation_with_injections_v2": {"instructions": page(tweets, None)}}}
    out = run(["thread", "1", "--json"], {"TweetDetail": [ans]})
    assert [t["id"] for t in json.loads(out.output)] == ["1", "2"]


def test_thread_replies(run):
    tweets = [tweet_result("1"), tweet_result("3", author="9999", handle="other",
                                              legacy={"in_reply_to_status_id_str": "1"})]
    ans = {"data": {"threaded_conversation_with_injections_v2": {"instructions": page(tweets, None)}}}
    out = run(["thread", "1", "--replies", "--json"], {"TweetDetail": [ans]})
    assert [t["id"] for t in json.loads(out.output)["replies"]] == ["3"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q", "-p", "no:cacheprovider"]))
