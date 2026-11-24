"""prompt-injection-guard's TF-IDF model, scored with NumPy alone.

That project exports its model in a data-only format (`guard-tfidf-v1`: JSON vocabularies,
safetensors weights, a manifest of SHA-256s). Its own loader rebuilds scikit-learn objects; this
one does the same arithmetic directly, so the firewall doesn't need scikit-learn at run time.
tests/test_checks_injection_model.py checks the scores equal scikit-learn's to 1e-12.

What scikit-learn does, and so what this does:
- words: lower-case, tokens matching (?u)\\b\\w\\w+\\b, then 1- and 2-grams joined by a space;
- chars (char_wb): runs of 2+ whitespace collapsed, each word padded with a space on both
  sides, then 3- to 5-grams within it (a word shorter than n counts once);
- per part: counts of known terms, 1 + ln(count), times idf, L2-normalised;
- the two parts side by side, then a logistic regression.
"""

import hashlib
import hmac
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import numpy as np

FORMAT = "guard-tfidf-v1"
FILES = ("config.json", "vocab_words.json", "vocab_chars.json", "weights.safetensors")
MANIFEST = "manifest.json"
EXPECTED = {
    "words": {"analyzer": "word", "ngram_range": [1, 2]},
    "chars": {"analyzer": "char_wb", "ngram_range": [3, 5]},
}
COMMON = {"sublinear_tf": True, "lowercase": True, "norm": "l2", "smooth_idf": True}
TOKEN = re.compile(r"(?u)\b\w\w+\b")
RUNS_OF_SPACE = re.compile(r"\s\s+")


class ModelIntegrityError(RuntimeError):
    """The model files don't match their pinned hashes, or aren't the expected format."""


def word_terms(text: str) -> list[str]:
    tokens = TOKEN.findall(text.lower())
    return tokens + [f"{a} {b}" for a, b in zip(tokens, tokens[1:], strict=False)]


def char_terms(text: str, low: int = 3, high: int = 5) -> list[str]:
    terms = []
    for word in RUNS_OF_SPACE.sub(" ", text.lower()).split():
        padded = f" {word} "
        for n in range(low, high + 1):
            offset = 0
            terms.append(padded[offset : offset + n])
            while offset + n < len(padded):
                offset += 1
                terms.append(padded[offset : offset + n])
            if offset == 0:  # word shorter than n: counted once, as scikit-learn does
                break
    return terms


def _part(terms: list[str], vocab: dict[str, int], idf: np.ndarray) -> dict[int, float]:
    counts = Counter(vocab[t] for t in terms if t in vocab)
    weights = {col: (1.0 + math.log(n)) * idf[col] for col, n in counts.items()}
    norm = math.sqrt(sum(w * w for w in weights.values()))
    return {col: w / norm for col, w in weights.items()} if norm else {}


@dataclass(frozen=True)
class InjectionModel:
    words: dict[str, int]
    chars: dict[str, int]
    idf_words: np.ndarray
    idf_chars: np.ndarray
    coef: np.ndarray  # words' columns, then chars'
    intercept: float
    threshold: float  # at or above: an injection
    review: float  # at or above: worth a closer look

    def score(self, text: str) -> float:
        """Probability that `text` (already normalised) is an injection."""
        offset = len(self.words)
        total = self.intercept
        for col, w in _part(word_terms(text), self.words, self.idf_words).items():
            total += w * self.coef[col]
        for col, w in _part(char_terms(text), self.chars, self.idf_chars).items():
            total += w * self.coef[offset + col]
        return 1.0 / (1.0 + math.exp(-total))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(model_dir: Path, manifest_sha256: str) -> InjectionModel:
    """Only if the manifest matches the pinned hash and every file matches the manifest. Each
    file is read once, and the bytes that were hashed are the bytes that are used."""
    from safetensors.numpy import load as load_tensors

    if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256 or ""):
        raise ModelIntegrityError("a pinned manifest SHA-256 (64 hex characters) is required")
    try:
        raw = (model_dir / MANIFEST).read_bytes()
    except OSError as exc:
        raise ModelIntegrityError(f"no {MANIFEST} in {model_dir}") from exc
    if not hmac.compare_digest(_sha(raw), manifest_sha256):
        raise ModelIntegrityError("the manifest doesn't match the pinned hash; not loading")
    manifest = json.loads(raw)
    if manifest.get("format") != FORMAT or set(manifest.get("files", {})) != set(FILES):
        raise ModelIntegrityError("unknown format or file list")
    data: dict[str, bytes] = {}
    for name in FILES:
        try:
            blob = (model_dir / name).read_bytes()
        except OSError as exc:
            raise ModelIntegrityError(f"{name} is missing") from exc
        if not hmac.compare_digest(_sha(blob), manifest["files"][name]):
            raise ModelIntegrityError(f"{name} doesn't match the manifest")
        data[name] = blob

    config = json.loads(data["config.json"])
    for part, expected in EXPECTED.items():
        if config["features"][part] != {**expected, **COMMON}:
            raise ModelIntegrityError(f"{part}: settings this scorer doesn't reproduce")
    tensors = load_tensors(data["weights.safetensors"])
    words = json.loads(data["vocab_words.json"])
    chars = json.loads(data["vocab_chars.json"])
    for vocab, idf in ((words, tensors["idf_words"]), (chars, tensors["idf_chars"])):
        if len(vocab) != idf.shape[0] or sorted(vocab.values()) != list(range(len(vocab))):
            raise ModelIntegrityError("a vocabulary doesn't match its idf weights")
    coef = tensors["coef"].reshape(-1)
    if coef.shape[0] != len(words) + len(chars):
        raise ModelIntegrityError("the weights don't match the vocabularies")
    threshold, review = float(config["threshold"]), float(config["review_threshold"])
    if not 0 < review <= threshold <= 1:
        raise ModelIntegrityError("thresholds out of order")
    return InjectionModel(
        words,
        chars,
        tensors["idf_words"],
        tensors["idf_chars"],
        coef,
        float(tensors["intercept"].reshape(-1)[0]),
        threshold,
        review,
    )
