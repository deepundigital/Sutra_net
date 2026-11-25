"""
Mobile & Chat Database Parser: Ingests Android SQLite dumps (WhatsApp msgstore.db,
SMS mmssms.db, and Telegram cache) into normalized message timelines.
"""

import sqlite3
import datetime
import json
import math
from pathlib import Path
from typing import List, Dict, Any, Optional


class MobileParser:
    """
    Extracts forensic message records from Android SQLite database dumps.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        if not self.db_path.is_file():
            raise FileNotFoundError(f"Mobile database not found: {db_path}")

    @staticmethod
    def _location_columns(cursor: sqlite3.Cursor, table: str) -> dict[str, str | None]:
        cursor.execute(f"PRAGMA table_info({table});")
        columns = {row[1] for row in cursor.fetchall()}
        return {
            "latitude": next((name for name in ("latitude", "lat") if name in columns), None),
            "longitude": next((name for name in ("longitude", "lon", "lng") if name in columns), None),
            "location": next((name for name in ("location", "location_json", "geo_location") if name in columns), None),
            "accuracy": next((name for name in ("location_accuracy", "accuracy_m", "accuracy") if name in columns), None),
        }

    @staticmethod
    def _make_location(latitude, longitude, raw_location=None, accuracy=None):
        if latitude is not None and longitude is not None:
            try:
                latitude_value = float(latitude)
                longitude_value = float(longitude)
                if -90 <= latitude_value <= 90 and -180 <= longitude_value <= 180:
                    try:
                        accuracy_value = float(accuracy) if accuracy is not None else None
                    except (TypeError, ValueError):
                        accuracy_value = None
                    if accuracy_value is not None and (
                        not math.isfinite(accuracy_value) or accuracy_value < 0
                    ):
                        accuracy_value = None
                    return {
                        "latitude": latitude_value,
                        "longitude": longitude_value,
                        "accuracy_m": accuracy_value,
                        "method": "whatsapp_location_fields",
                    }
            except (TypeError, ValueError):
                pass

        if isinstance(raw_location, bytes):
            raw_location = raw_location.decode("utf-8", errors="ignore")
        if isinstance(raw_location, str):
            try:
                raw_location = json.loads(raw_location)
            except (TypeError, ValueError):
                return raw_location if "," in raw_location else None
        if isinstance(raw_location, dict):
            latitude_value = raw_location.get("latitude")
            if latitude_value is None:
                latitude_value = raw_location.get("lat")
            longitude_value = raw_location.get("longitude")
            if longitude_value is None:
                longitude_value = raw_location.get("lon", raw_location.get("lng"))
            try:
                latitude_value = float(latitude_value)
                longitude_value = float(longitude_value)
            except (TypeError, ValueError):
                return None
            if -90 <= latitude_value <= 90 and -180 <= longitude_value <= 180:
                try:
                    accuracy_value = float(raw_location.get("accuracy_m")) if raw_location.get("accuracy_m") is not None else None
                except (TypeError, ValueError):
                    accuracy_value = None
                if accuracy_value is not None and (not math.isfinite(accuracy_value) or accuracy_value < 0):
                    accuracy_value = None
                return {
                    "latitude": latitude_value,
                    "longitude": longitude_value,
                    "accuracy_m": accuracy_value,
                    "method": str(raw_location.get("method") or "whatsapp_location_record"),
                }
        return None

    def parse_whatsapp(self) -> List[Dict[str, Any]]:
        """
        Extracts messages, timestamps, and sender JIDs from WhatsApp msgstore.db.
        """
        records: List[Dict[str, Any]] = []
        conn = sqlite3.connect(f"file:{self.db_path.resolve()}?mode=ro", uri=True)
        cursor = conn.cursor()

        # Check existing tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]

        if "message" in tables and "jid" in tables:
            # Modern schema
            location_columns = self._location_columns(cursor, "message")
            optional_selects = []
            for output_name in ("latitude", "longitude", "location", "accuracy"):
                column = location_columns[output_name]
                expression = f'm."{column}"' if column else "NULL"
                optional_selects.append(f"{expression} AS {output_name}")
            optional_conditions = []
            if location_columns["latitude"] and location_columns["longitude"]:
                optional_conditions.append(
                    f'(m."{location_columns["latitude"]}" IS NOT NULL '
                    f'AND m."{location_columns["longitude"]}" IS NOT NULL)'
                )
            if location_columns["location"]:
                optional_conditions.append(f'm."{location_columns["location"]}" IS NOT NULL')
            evidence_condition = "m.text_data IS NOT NULL"
            if optional_conditions:
                evidence_condition += " OR " + " OR ".join(optional_conditions)
            query = """
            SELECT 
                m._id, 
                m.timestamp, 
                j.raw_string AS sender_jid, 
                m.text_data,
                m.from_me,
            """ + ", ".join(optional_selects) + f"""
            FROM message m
            LEFT JOIN jid j ON m.sender_jid_row_id = j._id
            WHERE ({evidence_condition})
            ORDER BY m.timestamp ASC;
            """
            try:
                cursor.execute(query)
                for row in cursor.fetchall():
                    msg_id, ts, sender, text, from_me, latitude, longitude, raw_location, accuracy = row
                    phone = sender.split("@")[0] if sender else "Unknown"
                    location = self._make_location(latitude, longitude, raw_location, accuracy)
                    record = {
                        "msg_id": msg_id,
                        "source": "whatsapp",
                        "timestamp_ms": ts,
                        "datetime_utc": datetime.datetime.fromtimestamp(ts / 1000.0, datetime.timezone.utc).isoformat() if ts else None,
                        "sender": phone,
                        "from_me": bool(from_me),
                        "text": text,
                    }
                    if location is not None:
                        record["location"] = location
                    records.append(record)
            except Exception as e:
                # Try fallback legacy schema
                pass

        elif "messages" in tables:
            # Legacy WhatsApp schema
            location_columns = self._location_columns(cursor, "messages")
            optional_selects = []
            for output_name in ("latitude", "longitude", "location", "accuracy"):
                column = location_columns[output_name]
                expression = f'm."{column}"' if column else "NULL"
                optional_selects.append(f"{expression} AS {output_name}")
            optional_conditions = []
            if location_columns["latitude"] and location_columns["longitude"]:
                optional_conditions.append(
                    f'(m."{location_columns["latitude"]}" IS NOT NULL '
                    f'AND m."{location_columns["longitude"]}" IS NOT NULL)'
                )
            if location_columns["location"]:
                optional_conditions.append(f'm."{location_columns["location"]}" IS NOT NULL')
            evidence_condition = "m.data IS NOT NULL"
            if optional_conditions:
                evidence_condition += " OR " + " OR ".join(optional_conditions)
            query = """
            SELECT m._id, m.key_remote_jid, m.timestamp, m.data, m.key_from_me,
            """ + ", ".join(optional_selects) + f"""
            FROM messages m
            WHERE ({evidence_condition})
            ORDER BY m.timestamp ASC;
            """
            cursor.execute(query)
            for row in cursor.fetchall():
                msg_id, jid, ts, text, from_me, latitude, longitude, raw_location, accuracy = row
                phone = jid.split("@")[0] if jid else "Unknown"
                location = self._make_location(latitude, longitude, raw_location, accuracy)
                record = {
                    "msg_id": msg_id,
                    "source": "whatsapp_legacy",
                    "timestamp_ms": ts,
                    "datetime_utc": datetime.datetime.fromtimestamp(ts / 1000.0, datetime.timezone.utc).isoformat() if ts else None,
                    "sender": phone,
                    "from_me": bool(from_me),
                    "text": text,
                }
                if location is not None:
                    record["location"] = location
                records.append(record)

        conn.close()
        return records

    def parse_sms(self) -> List[Dict[str, Any]]:
        """
        Extracts SMS messages from Android mmssms.db.
        """
        records: List[Dict[str, Any]] = []
        conn = sqlite3.connect(f"file:{self.db_path.resolve()}?mode=ro", uri=True)
        cursor = conn.cursor()

        query = """
        SELECT _id, address, date, body, type
        FROM sms
        WHERE body IS NOT NULL
        ORDER BY date ASC;
        """
        try:
            cursor.execute(query)
            for row in cursor.fetchall():
                msg_id, address, date_val, body, msg_type = row
                records.append({
                    "msg_id": msg_id,
                    "source": "sms",
                    "timestamp_ms": date_val,
                    "datetime_utc": datetime.datetime.fromtimestamp(date_val / 1000.0, datetime.timezone.utc).isoformat() if date_val else None,
                    "sender": address,
                    "is_incoming": (msg_type == 1),
                    "text": body
                })
        except Exception:
            pass

        conn.close()
        return records
