from __future__ import annotations

from pathlib import Path
import joblib


# These paths point to the files created by backend/train.py after model training finishes.
ARTIFACTS_DIR = Path(__file__).resolve().parents[1] / "artifacts"
VECTORIZER_PATH = ARTIFACTS_DIR / "vectorizer.joblib"
CLASSIFIER_PATH = ARTIFACTS_DIR / "classifier.joblib"


# The API calls this helper at startup so prediction requests can reuse the same model in memory.
def load_artifacts():
    # If either artifact is missing, the backend falls back to pretraining rule-only scoring.
    if not VECTORIZER_PATH.exists() or not CLASSIFIER_PATH.exists():
        raise FileNotFoundError(
            "Model artifacts not found. Run training first: python backend/train.py"
        )
    # joblib restores the exact scikit-learn vectorizer and classifier saved during training.
    vectorizer = joblib.load(VECTORIZER_PATH)
    classifier = joblib.load(CLASSIFIER_PATH)
    return vectorizer, classifier
