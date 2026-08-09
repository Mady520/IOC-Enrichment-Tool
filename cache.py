"""
cache.py - Two persistence helpers used by enrich.py.

IOCCache   - Stores API results so the same IOC is never queried twice
             across multiple runs. Results expire after ttl_days.

IOCHistory - Tracks every IOC ever processed so the report can label
             an IOC as NEW (first time seen) or SEEN (appeared before).
"""

import json
import os
import time


class IOCCache:
    """
    File-backed cache for API results.

    Flow:
      1. Before any API call: cache.get(key) → returns result or None
      2. After API call:      cache.set(key, result)
      3. End of run:          cache.save()   (writes to disk once)

    Saving once at the end is intentional - disk writes are batched
    rather than happening after every individual API call.
    """

    def __init__(self, cache_file, ttl_days=7):
        self.file  = cache_file
        self.ttl   = ttl_days * 86400  # seconds
        self.data  = self._load()
        self._dirty = False

    def _load(self):
        if os.path.exists(self.file):
            try:
                with open(self.file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def get(self, key):
        """Return cached result if it exists and has not expired. None otherwise."""
        entry = self.data.get(key)
        if entry and (time.time() - entry.get("timestamp", 0)) < self.ttl:
            return entry["result"]
        return None

    def set(self, key, result):
        self.data[key]  = {"result": result, "timestamp": time.time()}
        self._dirty     = True

    def save(self):
        """Flush in-memory cache to disk. Call once at the end of a run."""
        if not self._dirty:
            return
        with open(self.file, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        self._dirty = False

    def size(self):
        return len(self.data)


class IOCHistory:
    """
    Tracks every IOC that has ever been processed, across all runs.

    Each entry stores:
      first_seen - ISO timestamp of the first encounter
      last_seen  - ISO timestamp of the most recent encounter
      severity   - worst severity ever assigned (escalates, never de-escalates)
      count      - total number of times this IOC has appeared

    is_new() is called BEFORE mark_seen() so that the "new" flag reflects whether the IOC existed in history from a PREVIOUS run, not this one.
    """

    _SEVERITY_RANK = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    def __init__(self, history_file):
        self.file   = history_file
        self.data   = self._load()
        self._dirty = False

    def _load(self):
        if os.path.exists(self.file):
            try:
                with open(self.file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def is_new(self, value):
        """True if this IOC has never been seen in any previous run."""
        return value not in self.data

    def mark_seen(self, value, severity):
        from datetime import datetime
        now = datetime.now().isoformat()

        if value in self.data:
            existing     = self.data[value]
            # Severity only ever escalates — never downgrades a previous HIGH to LOW
            old_rank     = self._SEVERITY_RANK.get(existing.get("severity", "CLEAN"), 0)
            new_rank     = self._SEVERITY_RANK.get(severity, 0)
            final_sev    = severity if new_rank > old_rank else existing["severity"]
            self.data[value].update({
                "last_seen": now,
                "severity":  final_sev,
                "count":     existing.get("count", 1) + 1,
            })
        else:
            self.data[value] = {
                "first_seen": now,
                "last_seen":  now,
                "severity":   severity,
                "count":      1,
            }
        self._dirty = True

    def get(self, value):
        """Return history entry dict, or None if never seen."""
        return self.data.get(value)

    def save(self):
        if not self._dirty:
            return
        with open(self.file, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        self._dirty = False

    def total_tracked(self):
        return len(self.data)
