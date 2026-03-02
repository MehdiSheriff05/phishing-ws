from __future__ import annotations

from pathlib import Path
import joblib


ARTIFACTS_DIR = Path(__file__).resolve().parents[1] / "artifacts"
VECTORIZER_PATH = ARTIFACTS_DIR / "vectorizer.joblib"
CLASSIFIER_PATH = ARTIFACTS_DIR / "classifier.joblib"


def load_artifacts():
    if not VECTORIZER_PATH.exists() or not CLASSIFIER_PATH.exists():
        raise FileNotFoundError(
            "Model artifacts not found. Run training first: python backend/train.py"
        )
    vectorizer = joblib.load(VECTORIZER_PATH)
    classifier = joblib.load(CLASSIFIER_PATH)
    return vectorizer, classifier
