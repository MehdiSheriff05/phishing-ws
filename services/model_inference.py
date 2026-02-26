from dataclasses import dataclass
from typing import Dict, List

PHISHING_KEYWORDS = [
    "urgent",
    "verify",
    "login",
    "reset",
    "suspended",
    "click below",
    "confirm",
    "invoice",
    "password",
    "account",
]


@dataclass
class TextInferenceConfig:
    model_name: str = "distilbert-base-uncased"
    max_tokens: int = 256
    stride: int = 64
    aggregation: str = "mean"  # mean | max
    enable_transformer: bool = False


class PhishingTextClassifier:
    def __init__(self, cfg: TextInferenceConfig):
        self.cfg = cfg
        self.device = "cpu"
        self._tokenizer_available = True
        self.tokenizer = None

        if not cfg.enable_transformer:
            self._tokenizer_available = False
        else:
            try:
                from transformers import AutoTokenizer

                self.tokenizer = AutoTokenizer.from_pretrained(cfg.model_name)
            except Exception:
                # Fallback keeps prototype runnable when tokenizer/model downloads are unavailable.
                self._tokenizer_available = False

        # TODO: Load a fine-tuned checkpoint when available.
        # TODO: Import and use torch once runtime/OpenMP environment is configured.
        # Example:
        # import torch
        # self.device = "cuda" if torch.cuda.is_available() else "cpu"
        # self.model = AutoModelForSequenceClassification.from_pretrained("<checkpoint-path>").to(self.device)
        # self.model.eval()

    def _keyword_score(self, text: str) -> float:
        lower = text.lower()
        hits = sum(1 for token in PHISHING_KEYWORDS if token in lower)
        caps_ratio = sum(1 for c in text if c.isupper()) / max(1, len(text))
        exclamations = text.count("!")

        score = min(1.0, (hits * 0.12) + (caps_ratio * 1.5) + min(0.2, exclamations * 0.01))
        return score

    def _chunk_text(self, text: str) -> List[str]:
        if not self._tokenizer_available or self.tokenizer is None:
            # Simple deterministic fallback chunking by character window.
            window = 1200
            stride = 300
            chunks: List[str] = []
            start = 0
            while start < len(text):
                chunks.append(text[start : start + window])
                start += max(1, window - stride)
            return chunks or [text]

        tokenized = self.tokenizer(
            text,
            truncation=False,
            return_overflowing_tokens=True,
            max_length=self.cfg.max_tokens,
            stride=self.cfg.stride,
        )

        chunks: List[str] = []
        for ids in tokenized["input_ids"]:
            chunks.append(self.tokenizer.decode(ids, skip_special_tokens=True))
        return chunks or [text]

    def score(self, subject: str, body_text: str) -> Dict:
        merged = f"{subject}\n{body_text}".strip()
        if not merged:
            return {"score": 0.0, "reasons": ["No text content found"], "chunk_count": 0}

        chunks = self._chunk_text(merged)
        chunk_scores = [self._keyword_score(chunk) for chunk in chunks]

        if self.cfg.aggregation == "max":
            final = max(chunk_scores)
        else:
            final = sum(chunk_scores) / len(chunk_scores)

        reasons = []
        if final >= 0.65:
            reasons.append("Email text uses high-pressure or credential-themed language")
        elif final >= 0.35:
            reasons.append("Email text includes some phishing-like wording")

        return {
            "score": round(final * 100, 2),
            "reasons": reasons,
            "chunk_count": len(chunks),
            "aggregation": self.cfg.aggregation,
        }
