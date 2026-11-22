"""Poll inert fixture endpoints using upstream JSON Feed and RSS field semantics."""
import json
import os
import sys
import urllib.request
import xml.etree.ElementTree as ET


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "saf-k8s-monitor-fixture/1"})
    with urllib.request.urlopen(request, timeout=5) as response:
        data = response.read(131073)
    if len(data) > 131072:
        raise ValueError("inert feed exceeded the size bound")
    return data


def check_json_feed(url):
    feed = json.loads(fetch(url))
    if feed.get("version") != "https://jsonfeed.org/version/1.1":
        raise ValueError("unsupported JSON Feed version")
    items = feed.get("items")
    if not isinstance(items, list) or not items:
        raise ValueError("JSON Feed has no items")
    for item in items:
        if not isinstance(item.get("id"), str) or not item["id"]:
            raise ValueError("JSON Feed item is missing required id")
    if not any(item.get("id", "").startswith("CVE-2099-") for item in items):
        raise ValueError("expected synthetic upstream item is missing")
    return len(items)


def check_rss(url):
    root = ET.fromstring(fetch(url))
    if root.tag != "rss" or root.get("version") != "2.0":
        raise ValueError("unsupported RSS version")
    channel = root.find("channel")
    items = [] if channel is None else channel.findall("item")
    if not items:
        raise ValueError("RSS channel has no items")
    for item in items:
        if not (item.findtext("title") or item.findtext("description")):
            raise ValueError("RSS item needs a title or description")
    if not any(item.findtext("title") == "SYNTHETIC provider bulletin metadata fixture"
               for item in items):
        raise ValueError("expected synthetic provider item is missing")
    return len(items)


def main():
    sources = (
        ("kubernetes-json-feed", check_json_feed, "KUBERNETES_FEED_URL"),
        ("aws-security-bulletin-rss", check_rss, "AWS_BULLETIN_URL"),
    )
    failed = False
    for source, check, location in sources:
        try:
            count = check(os.environ[location])
        except (OSError, ValueError, ET.ParseError) as error:
            http_status = getattr(error, "code", None)
            print(f"monitor_poll_failed source={source} status={http_status}", file=sys.stderr)
            failed = True
        else:
            print(f"source={source} items={count}")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
