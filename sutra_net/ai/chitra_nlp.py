"""
Chitra-NLP: Indigenous Mobile Forensics & Hinglish Fraud Classifier
Specialized for Indian LEA scenarios: extracts UPI VPAs, phone numbers, IFSC codes,
and scores Hinglish transliterated chat/SMS dumps for financial coercion and OTP scams.
"""

import re
from typing import List, Dict, Any, Set
from collections import Counter

from sutra_net.config import (
    UPI_VPA_REGEX,
    INDIAN_PHONE_REGEX,
    IFSC_REGEX,
    BANK_REF_REGEX,
    HINGLISH_SCAM_PATTERNS
)


class ChitraNLP:
    """
    NLP engine for Indian mobile chat artifacts, supporting Hinglish scam categorization
    and forensic entity extraction.
    """

    def __init__(self):
        self.upi_pattern = re.compile(UPI_VPA_REGEX, re.IGNORECASE)
        self.phone_pattern = re.compile(INDIAN_PHONE_REGEX)
        self.ifsc_pattern = re.compile(IFSC_REGEX)
        self.bank_ref_pattern = re.compile(BANK_REF_REGEX, re.IGNORECASE)
        self.amount_pattern = re.compile(r'(?:₹|Rs\.?|INR)\s*([0-9,]+(?:\.[0-9]{2})?)', re.IGNORECASE)
        self.coordinate_patterns = (
            re.compile(
                r"(?<![\w.])(?P<latitude>-?(?:90|[0-8]?\d)\.\d{2,})"
                r"\s*(?:,|%2[cC])\s*"
                r"(?P<longitude>-?(?:180|1[0-7]\d|[0-9]?\d)\.\d{2,})(?![\d.])"
            ),
            re.compile(
                r"!3d(?P<latitude>-?\d{1,2}\.\d{2,})!4d"
                r"(?P<longitude>-?\d{1,3}\.\d{2,})"
            ),
        )

    def extract_entities(self, text: str) -> Dict[str, Any]:
        """
        Extracts key financial and communication identifiers from raw text.
        """
        if not text:
            return {
                "upi_vpas": [],
                "phone_numbers": [],
                "ifsc_codes": [],
                "bank_references": [],
                "amounts": [],
                "locations": [],
            }

        # UPI VPAs
        raw_upis = self.upi_pattern.findall(text)
        upis = sorted(list(set(u.strip().lower() for u in raw_upis)))

        # Phones (normalize +91)
        raw_phones = self.phone_pattern.findall(text)
        phones = []
        for p in raw_phones:
            cleaned = re.sub(r'[\s\-+]', '', p)
            if cleaned.startswith("91") and len(cleaned) == 12:
                cleaned = cleaned[2:]
            if len(cleaned) == 10:
                phones.append(cleaned)
        phones = sorted(list(set(phones)))

        # IFSC
        ifscs = sorted(list(set(self.ifsc_pattern.findall(text))))

        # Bank Ref / UTR
        bank_refs = sorted(list(set(self.bank_ref_pattern.findall(text))))

        # Amounts
        amounts = sorted(list(set(self.amount_pattern.findall(text))))

        # Coordinates embedded in shared-map URLs or plain lat,lon text.
        locations_by_key = {}
        for pattern in self.coordinate_patterns:
            for match in pattern.finditer(text):
                latitude = float(match.group("latitude"))
                longitude = float(match.group("longitude"))
                if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
                    continue
                key = (round(latitude, 6), round(longitude, 6))
                locations_by_key[key] = {
                    "latitude": key[0],
                    "longitude": key[1],
                    "method": "coordinates_in_message",
                }

        result = {
            "upi_vpas": upis,
            "phone_numbers": phones,
            "ifsc_codes": ifscs,
            "bank_references": bank_refs,
            "amounts": amounts,
            "locations": [locations_by_key[key] for key in sorted(locations_by_key)],
        }

    def classify_hinglish_intent(self, text: str) -> Dict[str, Any]:
        """
        Scores message for fraud and extortion categories in Hinglish.
        """
        if not text:
            return {
                "fraud_score": 0.0,
                "primary_category": "BENIGN",
                "matched_indicators": [],
                "is_fraudulent": False
            }

        lower_text = text.lower()
        matched = []
        category_counts = Counter()

        for category, keywords in HINGLISH_SCAM_PATTERNS.items():
            for kw in keywords:
                if kw in lower_text:
                    matched.append(kw)
                    category_counts[category] += 1

        total_matches = len(matched)
        fraud_score = min(1.0, round(total_matches * 0.35, 2))

        primary_cat = category_counts.most_common(1)[0][0] if category_counts else "BENIGN"

        return {
            "fraud_score": fraud_score,
            "primary_category": primary_cat,
            "matched_indicators": matched,
            "is_fraudulent": (fraud_score >= 0.35)
        }

    def analyze_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Combines entity extraction and fraud categorization for an ingested chat/SMS record.
        """
        text = message.get("text", "")
        entities = self.extract_entities(text)
        intent = self.classify_hinglish_intent(text)

        result = {
            "msg_id": message.get("msg_id"),
            "source": message.get("source"),
            "sender": message.get("sender"),
            "timestamp": message.get("datetime_utc") or message.get("timestamp_ms"),
            "timestamp_ms": message.get("timestamp_ms"),
            "datetime_utc": message.get("datetime_utc"),
            "from_me": message.get("from_me"),
            "is_incoming": message.get("is_incoming"),
            "text": text,
            "entities": entities,
            "fraud_analysis": intent,
            "is_flagged": intent["is_fraudulent"] or bool(entities["upi_vpas"])
        }
        if message.get("location") is not None:
            result["location"] = message["location"]
        elif message.get("latitude") is not None and (
            message.get("longitude") is not None or message.get("lon") is not None
        ):
            result["location"] = {
                "latitude": message["latitude"],
                "longitude": message["longitude"] if message.get("longitude") is not None else message.get("lon"),
                "accuracy_m": message.get("accuracy_m"),
                "method": "structured_record",
            }
        return result

    def triage_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs batch analysis and sorts by fraud severity.
        """
        results = [self.analyze_message(m) for m in messages]
        results.sort(key=lambda x: x["fraud_analysis"]["fraud_score"], reverse=True)
        return results
