"""
Intel Pipeline — Feed Runner
Orchestrates all feed pulls in parallel with independent timeouts.
Called from the Flask UI via Pull All Feeds or individual feed buttons.
Returns per-feed status for the UI health strip.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from src.feeds.mitre         import MitreAttackFeed
from src.feeds.cisa_kev      import CisaKevFeed
from src.feeds.spamhaus       import SpamhausAsnDropFeed
from src.feeds.malwarebazaar  import MalwareBazaarFeed
from src.feeds.urlhaus        import URLhausFeed
from src.feeds.threatfox      import ThreatFoxFeed
from src.feeds.feodo          import FeodoTrackerFeed
from src.feeds.otx            import OTXFeed

# All automated feed instances
ALL_FEEDS = [
    MitreAttackFeed(),
    CisaKevFeed(),
    SpamhausAsnDropFeed(),
    MalwareBazaarFeed(),
    URLhausFeed(),
    ThreatFoxFeed(),
    FeodoTrackerFeed(),
    OTXFeed(),
]

# Feed name → instance map for individual pulls
FEED_MAP = {feed.name: feed for feed in ALL_FEEDS}


def run_all_feeds():
    """
    Pull all feeds in parallel. Each feed runs independently —
    one failure does not affect the others.
    Returns a list of result dicts, one per feed.
    """
    results = []
    with ThreadPoolExecutor(max_workers=len(ALL_FEEDS)) as executor:
        futures = {executor.submit(feed.run): feed.name for feed in ALL_FEEDS}
        for future in as_completed(futures):
            feed_name = futures[future]
            try:
                result = future.result()
            except Exception as e:
                result = {
                    "feed":    feed_name,
                    "status":  "failed",
                    "raw_count": 0,
                    "summary": {},
                    "error":   str(e),
                }
            results.append(result)

    return results


def run_single_feed(feed_name):
    """
    Pull a single feed by name. Used for analyst-initiated retry.
    Returns a single result dict.
    """
    feed = FEED_MAP.get(feed_name)
    if not feed:
        return {
            "feed":    feed_name,
            "status":  "failed",
            "raw_count": 0,
            "summary": {},
            "error":   f"Unknown feed: {feed_name}",
        }
    try:
        return feed.run()
    except Exception as e:
        return {
            "feed":    feed_name,
            "status":  "failed",
            "raw_count": 0,
            "summary": {},
            "error":   str(e),
        }
