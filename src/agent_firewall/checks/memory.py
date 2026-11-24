"""What the agent has read this session, kept only as keyed hashes, never as text.

Used by LK03 to notice tool output heading back out: a log line pasted into a URL, a key read
from a file put into an email. Two kinds of fingerprint:
- shingles: every run of 8 words, so a copied sentence or log line is recognised even inside
  other text;
- rare tokens: single words of 16+ letters and digits (keys, hashes, ids), which are too short
  to make a shingle but are exactly what a leak looks like.

The hash key is random per session, so the memory can't be checked against a list of guesses
afterwards, and it holds at most MAX_FINGERPRINTS (oldest dropped first).
"""

import hashlib
import os
import re
from collections import OrderedDict

SHINGLE_WORDS = 8
# "=" and "/" split tokens, so KEY=value in a file and ?k=value in a URL give the same token.
RARE_TOKEN = re.compile(r"[A-Za-z0-9_+-]{16,200}")
WORD = re.compile(r"[a-z0-9]+")
MAX_FINGERPRINTS = 100_000
MAX_TEXT_CHARS = 200_000


class OutputMemory:
    def __init__(self) -> None:
        self._key = os.urandom(16)
        self._seen: OrderedDict[bytes, None] = OrderedDict()

    def __len__(self) -> int:
        return len(self._seen)

    def _hash(self, item: str) -> bytes:
        return hashlib.blake2b(item.encode("utf-8"), key=self._key, digest_size=12).digest()

    def _fingerprints(self, text: str) -> set[bytes]:
        text = text[:MAX_TEXT_CHARS]
        words = WORD.findall(text.lower())
        prints = {
            self._hash("s:" + " ".join(words[i : i + SHINGLE_WORDS]))
            for i in range(len(words) - SHINGLE_WORDS + 1)
        }
        prints |= {
            self._hash("t:" + token)
            for token in RARE_TOKEN.findall(text)
            if any(c.isdigit() for c in token) and any(c.isalpha() for c in token)
        }
        return prints

    def remember(self, text: str) -> None:
        for fingerprint in self._fingerprints(text):
            self._seen[fingerprint] = None
            self._seen.move_to_end(fingerprint)
        while len(self._seen) > MAX_FINGERPRINTS:
            self._seen.popitem(last=False)

    def copied(self, text: str) -> int:
        """How many of this text's fingerprints were seen in earlier tool output."""
        return sum(1 for f in self._fingerprints(text) if f in self._seen)
