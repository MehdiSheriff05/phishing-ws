import os
from dataclasses import dataclass


@dataclass
class Config:
    HOST: str = os.getenv("FLASK_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("FLASK_PORT", "5000"))
    DEBUG: bool = os.getenv("FLASK_DEBUG", "true").lower() == "true"
    MODEL_NAME: str = os.getenv("MODEL_NAME", "distilbert-base-uncased")
    MODEL_PATH: str = os.getenv("MODEL_PATH", "")
    ENABLE_TRANSFORMER: bool = os.getenv("ENABLE_TRANSFORMER", "false").lower() == "true"
    MAX_TEXT_CHARS: int = int(os.getenv("MAX_TEXT_CHARS", "20000"))


config = Config()
