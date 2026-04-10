"""
Intel Pipeline — Base Feed Puller
All feed pullers inherit from BaseFeed.
Each puller implements pull() and returns a list of raw dicts with at minimum
'type' and 'value'. The base run() method handles normalisation, ingest, and
feed health logging.
"""

from datetime import datetime, timezone
from src.db.database import get_connection
from src.normalizer import normalize_entry
from src.db.ingest import ingest_batch


class BaseFeed:
    name        = "BaseFeed"
    tier        = 2
    base_weight = 70.0
    timeout     = 30       # seconds per HTTP request

    def pull(self):
        """
        Fetch raw indicators from the feed source.
        Must return a list of dicts, each with at minimum:
            {'type': str, 'value': str}
        Must return an empty list on failure — never raise from pull().
        """
        raise NotImplementedError

    def run(self):
        """
        Full pull cycle:
        1. Call pull() to fetch raw indicators
        2. Normalise each entry
        3. Ingest batch into the database
        4. Log result to feed_health
        Returns the ingest summary dict.
        """
        pull_at = datetime.now(timezone.utc).isoformat()
        raw_entries = []
        error_message = None

        try:
            raw_entries = self.pull()
        except Exception as e:
            error_message = str(e)
            raw_entries = []

        # Normalise
        normalized = []
        for raw in raw_entries:
            try:
                normalized.append(
                    normalize_entry(raw, self.name, self.tier, self.base_weight)
                )
            except Exception as e:
                error_message = error_message or str(e)

        # Ingest
        if normalized:
            summary = ingest_batch(normalized, self.name, self.tier)
        else:
            summary = {
                "inserted": 0, "updated_pending": 0, "updated_rereview": 0,
                "updated_informational": 0, "no_change": 0, "errors": 0
            }

        # Log to feed_health
        status = "success" if not error_message and raw_entries else (
            "empty" if not error_message else "failed"
        )
        self._log_health(pull_at, status, summary, error_message)

        return {
            "feed": self.name,
            "status": status,
            "raw_count": len(raw_entries),
            "summary": summary,
            "error": error_message,
        }

    def _log_health(self, pull_at, status, summary, error_message):
        conn = get_connection()
        conn.execute("""
            INSERT INTO feed_health
                (feed_name, pull_at, status, indicators_new, indicators_updated, error_message)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            self.name,
            pull_at,
            status,
            summary.get("inserted", 0),
            summary.get("updated_pending", 0) + summary.get("updated_rereview", 0),
            error_message,
        ))
        conn.commit()
        conn.close()
