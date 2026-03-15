"""Lightweight Prometheus metrics for IMAP MCP operations.

Tracks email triage operations without requiring the prometheus_client library.
Exposes metrics via a simple counter dict that can be scraped or logged.
"""

import time
import threading
from collections import defaultdict
from typing import Dict


class TriageMetrics:
    """Thread-safe metrics collector for email triage operations."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = defaultdict(int)
        self._start_time = time.time()

    def record_triage(self, category: str, count: int = 1) -> None:
        """Record triaged messages by category.

        Args:
            category: Classification category (e.g., 'political_spam', 'health_scam', 'marketing')
            count: Number of messages in this category
        """
        with self._lock:
            self._counters[f"imap_llm_mcp_triage_total{{category=\"{category}\"}}"] += count
            self._counters["imap_llm_mcp_triage_total"] += count

    def record_move(self, source: str, target: str, count: int = 1) -> None:
        """Record moved messages."""
        with self._lock:
            self._counters[f"imap_llm_mcp_moves_total{{source=\"{source}\",target=\"{target}\"}}"] += count
            self._counters["imap_llm_mcp_moves_total"] += count

    def record_search(self, folder: str) -> None:
        """Record search operations."""
        with self._lock:
            self._counters[f"imap_llm_mcp_searches_total{{folder=\"{folder}\"}}"] += 1
            self._counters["imap_llm_mcp_searches_total"] += 1

    def record_error(self, operation: str) -> None:
        """Record operation errors."""
        with self._lock:
            self._counters[f"imap_llm_mcp_errors_total{{operation=\"{operation}\"}}"] += 1
            self._counters["imap_llm_mcp_errors_total"] += 1

    def record_deny_hit(self, domain: str) -> None:
        """Record denylist matches for learning."""
        with self._lock:
            self._counters[f"imap_llm_mcp_denylist_hits_total{{domain=\"{domain}\"}}"] += 1
            self._counters["imap_llm_mcp_denylist_hits_total"] += 1

    def to_prometheus(self) -> str:
        """Export metrics in Prometheus text exposition format.

        Returns:
            Prometheus-compatible metrics string
        """
        with self._lock:
            lines = [
                "# HELP imap_llm_mcp_triage_total Total messages triaged",
                "# TYPE imap_llm_mcp_triage_total counter",
                "# HELP imap_llm_mcp_moves_total Total messages moved",
                "# TYPE imap_llm_mcp_moves_total counter",
                "# HELP imap_llm_mcp_searches_total Total search operations",
                "# TYPE imap_llm_mcp_searches_total counter",
                "# HELP imap_llm_mcp_errors_total Total operation errors",
                "# TYPE imap_llm_mcp_errors_total counter",
                "# HELP imap_llm_mcp_denylist_hits_total Denylist domain matches",
                "# TYPE imap_llm_mcp_denylist_hits_total counter",
                f"# HELP imap_llm_mcp_uptime_seconds Server uptime",
                f"# TYPE imap_llm_mcp_uptime_seconds gauge",
                f"imap_llm_mcp_uptime_seconds {time.time() - self._start_time:.1f}",
            ]
            for key, value in sorted(self._counters.items()):
                lines.append(f"{key} {value}")
            return "\n".join(lines) + "\n"

    def summary(self) -> Dict[str, int]:
        """Return metrics as a dict for logging/inspection."""
        with self._lock:
            return dict(self._counters)


# Global metrics instance
metrics = TriageMetrics()
