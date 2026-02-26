"""
NLP Phishing Classifier
───────────────────────
Two-tier approach:
  Tier 1: HuggingFace Transformers — DistilBERT fine-tuned for phishing detection
           (best accuracy, requires ~260MB model download on first run)
  Tier 2: scikit-learn TF-IDF + Logistic Regression fallback
           (fast, no GPU needed, good baseline)

The classifier assigns a probability score [0.0 – 1.0] for the email being phishing.

Optional NLTK preprocessing: tokenization, stopword removal, stemming.
"""
import logging
import re
from typing import Optional
from config import Config


class PhishingClassifier:
    """
    HuggingFace Transformers primary classifier with scikit-learn fallback.
    """

    PHISHING_KEYWORDS = [
        "verify", "account", "suspended", "login", "credential", "password",
        "urgent", "immediately", "click here", "confirm", "unusual activity",
        "bank", "payment", "update", "expires", "security", "unauthorized",
        "winner", "congratulations", "prize", "free", "limited time",
    ]

    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._transformer_pipeline = None
        self._sklearn_model = None
        self._use_transformer = True

        self._init_model()

    def _init_model(self):
        """Try to load HuggingFace transformer, fall back to sklearn."""
        try:
            from transformers import pipeline  # type: ignore
            self.logger.info(f"Loading NLP model: {self.config.nlp_model}")
            device = 0 if self.config.use_gpu else -1

            # Try a phishing-specific model first, then fall back to sentiment
            try:
                self._transformer_pipeline = pipeline(
                    "text-classification",
                    model="ealvaradob/bert-finetuned-phishing",
                    device=device,
                    truncation=True,
                    max_length=512
                )
                self.logger.info("Loaded phishing-specific BERT model")
            except Exception:
                # Fall back to general sentiment (negative → phishing signal)
                self._transformer_pipeline = pipeline(
                    "text-classification",
                    model=self.config.nlp_model,
                    device=device,
                    truncation=True,
                    max_length=512
                )
                self.logger.info(f"Loaded sentiment model: {self.config.nlp_model}")

        except ImportError:
            self.logger.info("Transformers not installed — using scikit-learn fallback")
            self._use_transformer = False
            self._init_sklearn()
        except Exception as e:
            self.logger.warning(f"Could not load transformer model: {e}. Using sklearn fallback.")
            self._use_transformer = False
            self._init_sklearn()

    def _init_sklearn(self):
        """
        Initialize a simple TF-IDF + LogisticRegression classifier.
        NOTE: This is pre-trained with synthetic data for demonstration.
        In production, train on a real phishing corpus (e.g., APWG, PhishTank dataset).
        """
        try:
            from sklearn.pipeline import Pipeline  # type: ignore
            from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
            from sklearn.linear_model import LogisticRegression  # type: ignore
            import numpy as np  # type: ignore

            # Minimal synthetic training data (replace with real dataset in production)
            phishing_samples = [
                "verify your account immediately or it will be suspended",
                "click here to confirm your banking credentials",
                "your paypal account has been limited please update payment info",
                "unusual sign in activity detected verify your identity now",
                "your account will be closed unless you confirm your details",
                "congratulations you have been selected free gift card click here",
                "dear customer your password expires today click to reset",
            ]
            legitimate_samples = [
                "meeting tomorrow at 3pm please bring the quarterly report",
                "hi just checking in about the project status update",
                "your order has shipped tracking number included",
                "the team lunch is scheduled for friday please rsvp",
                "newsletter from our company updates and product news",
                "invoice attached please review at your convenience",
                "thank you for your purchase your receipt is attached",
            ]

            X = phishing_samples + legitimate_samples
            y = [1]*len(phishing_samples) + [0]*len(legitimate_samples)

            self._sklearn_model = Pipeline([
                ("tfidf", TfidfVectorizer(ngram_range=(1,2), min_df=1, max_features=5000)),
                ("clf", LogisticRegression(C=1.0, max_iter=1000))
            ])
            self._sklearn_model.fit(X, y)
            self.logger.info("scikit-learn TF-IDF + LR classifier ready")

        except ImportError:
            self.logger.warning("scikit-learn not installed; NLP detection disabled")

    def _preprocess(self, text: str) -> str:
        """Basic text preprocessing with optional NLTK."""
        text = text.lower()
        text = re.sub(r"http\S+", " URL ", text)
        text = re.sub(r"\S+@\S+", " EMAIL ", text)
        text = re.sub(r"[^a-z0-9\s]", " ", text)
        text = re.sub(r"\s+", " ", text).strip()

        try:
            import nltk  # type: ignore
            from nltk.corpus import stopwords  # type: ignore
            from nltk.stem import PorterStemmer  # type: ignore

            # Download if not available
            for resource in ["stopwords", "punkt"]:
                try:
                    nltk.data.find(f"corpora/{resource}" if resource == "stopwords" else f"tokenizers/{resource}")
                except LookupError:
                    nltk.download(resource, quiet=True)

            tokens = text.split()
            stop_words = set(stopwords.words("english"))
            # Keep threat-relevant stop words
            keep = {"not", "no", "never", "immediately", "urgent", "now"}
            tokens = [t for t in tokens if t not in stop_words or t in keep]
            stemmer = PorterStemmer()
            tokens = [stemmer.stem(t) for t in tokens]
            text = " ".join(tokens)
        except ImportError:
            pass
        except Exception:
            pass

        return text

    def predict(self, text: str) -> float:
        """Return phishing probability score [0.0 – 1.0]."""
        if not text or not text.strip():
            return 0.0

        processed = self._preprocess(text)

        if self._use_transformer and self._transformer_pipeline:
            return self._predict_transformer(text)  # Use raw text for transformer
        elif self._sklearn_model:
            return self._predict_sklearn(processed)
        else:
            return self._keyword_fallback(text)

    def _predict_transformer(self, text: str) -> float:
        try:
            result = self._transformer_pipeline(text[:512])[0]
            label = result["label"].upper()
            score = result["score"]

            # Handle phishing-specific model labels
            if label in ("PHISHING", "MALICIOUS", "LABEL_1"):
                return score
            # Handle sentiment model (NEGATIVE sentiment → potential phishing)
            elif label == "NEGATIVE":
                return score * 0.6  # Dampen — negative ≠ always phishing
            elif label in ("POSITIVE", "LEGITIMATE", "LABEL_0"):
                return 1.0 - score
            else:
                return 0.5
        except Exception as e:
            self.logger.debug(f"Transformer predict error: {e}")
            return self._keyword_fallback(text)

    def _predict_sklearn(self, text: str) -> float:
        try:
            proba = self._sklearn_model.predict_proba([text])[0]
            return float(proba[1])  # Probability of class 1 (phishing)
        except Exception as e:
            self.logger.debug(f"sklearn predict error: {e}")
            return 0.0

    def _keyword_fallback(self, text: str) -> float:
        """Absolute fallback: keyword counting heuristic."""
        text_lower = text.lower()
        hits = sum(1 for kw in self.PHISHING_KEYWORDS if kw in text_lower)
        return min(1.0, hits * 0.08)
