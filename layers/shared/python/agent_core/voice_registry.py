from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError


_dynamodb = boto3.resource("dynamodb")
_cached_table = None
_cached_table_name: Optional[str] = None


def _get_table():
    global _cached_table, _cached_table_name
    table_name = os.environ.get("AGENT_STATE_TABLE")
    if not table_name:
        return None
    if _cached_table is None or _cached_table_name != table_name:
        _cached_table_name = table_name
        _cached_table = _dynamodb.Table(table_name)
    return _cached_table


def _now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sanitize_decimal(obj: Any) -> Any:
    """Convert floats to Decimals for DynamoDB."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _sanitize_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_decimal(v) for v in obj]
    return obj


@dataclass
class SpeakerProfile:
    """Complete speaker profile with all associated data."""
    speaker_id: str
    agent_id: str
    speaker_name: Optional[str] = None
    first_seen_ts: Optional[str] = None
    last_seen_ts: Optional[str] = None
    interaction_count: int = 0
    notes: Optional[str] = None
    preferences: Dict[str, Any] = field(default_factory=dict)
    voice_samples: List[str] = field(default_factory=list)  # S3 keys of voice samples
    enrollment_status: str = "unknown"  # unknown, partial, enrolled
    embedding_version: Optional[str] = None
    custom_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in {
            "speaker_id": self.speaker_id,
            "agent_id": self.agent_id,
            "speaker_name": self.speaker_name,
            "first_seen_ts": self.first_seen_ts,
            "last_seen_ts": self.last_seen_ts,
            "interaction_count": self.interaction_count,
            "notes": self.notes,
            "preferences": self.preferences if self.preferences else None,
            "voice_samples": self.voice_samples if self.voice_samples else None,
            "enrollment_status": self.enrollment_status,
            "embedding_version": self.embedding_version,
            "custom_data": self.custom_data if self.custom_data else None,
        }.items() if v is not None}

    @classmethod
    def from_item(cls, item: Dict[str, Any]) -> "SpeakerProfile":
        """Create SpeakerProfile from DynamoDB item."""
        return cls(
            speaker_id=item.get("sk") or item.get("speaker_id", ""),
            agent_id=item.get("agent_id", ""),
            speaker_name=item.get("speaker_name"),
            first_seen_ts=item.get("first_seen_ts"),
            last_seen_ts=item.get("last_seen_ts"),
            interaction_count=int(item.get("interaction_count", 0)),
            notes=item.get("notes"),
            preferences=item.get("preferences", {}),
            voice_samples=item.get("voice_samples", []),
            enrollment_status=item.get("enrollment_status", "unknown"),
            embedding_version=item.get("embedding_version"),
            custom_data=item.get("custom_data", {}),
        )


class VoiceRegistry:
    """Enhanced voice registry with multi-speaker support.

    Key Schema:
    - Speakers: pk=AGENT#{agent_id}#VOICE, sk={speaker_id}
    - Voice samples: pk=VOICE_SAMPLE#{agent_id}, sk={sample_id}

    Features:
    - Speaker profile management
    - Voice enrollment with multiple samples
    - Speaker identification via voice embedding matching
    - Interaction tracking
    - Cross-session speaker persistence
    """

    # Enrollment thresholds
    MIN_SAMPLES_FOR_ENROLLMENT = 3
    EMBEDDING_SIMILARITY_THRESHOLD = 0.85

    def __init__(self, table_name: Optional[str] = None):
        self.table_name = table_name or os.environ.get("AGENT_STATE_TABLE")
        self._table = None

    @property
    def table(self):
        if self._table is None and self.table_name:
            self._table = _dynamodb.Table(self.table_name)
        return self._table

    def _speaker_pk(self, agent_id: str) -> str:
        return f"AGENT#{agent_id}#VOICE"

    def get_speaker_profile(
        self,
        agent_id: str,
        speaker_id: str,
    ) -> Optional[SpeakerProfile]:
        """Get a speaker's full profile.

        Args:
            agent_id: Agent identifier
            speaker_id: Speaker identifier (voice_id or custom ID)

        Returns:
            SpeakerProfile or None if not found
        """
        if not self.table:
            return None

        pk = self._speaker_pk(agent_id)

        try:
            resp = self.table.get_item(Key={"pk": pk, "sk": speaker_id})
            item = resp.get("Item")
            if item:
                return SpeakerProfile.from_item(item)
        except ClientError as e:
            logging.error("get_speaker_profile: query failed: %s", e)

        return None

    def create_or_update_speaker(
        self,
        agent_id: str,
        speaker_id: str,
        speaker_name: Optional[str] = None,
        notes: Optional[str] = None,
        preferences: Optional[Dict[str, Any]] = None,
        custom_data: Optional[Dict[str, Any]] = None,
    ) -> SpeakerProfile:
        """Create or update a speaker profile.

        Args:
            agent_id: Agent identifier
            speaker_id: Speaker identifier
            speaker_name: Human-readable name
            notes: Agent notes about the speaker
            preferences: Speaker preferences
            custom_data: Additional custom data

        Returns:
            Updated SpeakerProfile
        """
        if not self.table:
            raise ValueError("DynamoDB table not configured")

        pk = self._speaker_pk(agent_id)
        now = _now_iso()

        # Get existing profile if any
        existing = self.get_speaker_profile(agent_id, speaker_id)

        if existing:
            # Update existing profile
            update_expr_parts = ["SET last_seen_ts = :now", "interaction_count = interaction_count + :one"]
            expr_values: Dict[str, Any] = {":now": now, ":one": 1}

            if speaker_name:
                update_expr_parts.append("speaker_name = :name")
                expr_values[":name"] = speaker_name
            if notes is not None:
                update_expr_parts.append("notes = :notes")
                expr_values[":notes"] = notes
            if preferences is not None:
                update_expr_parts.append("preferences = :prefs")
                expr_values[":prefs"] = _sanitize_decimal(preferences)
            if custom_data is not None:
                update_expr_parts.append("custom_data = :custom")
                expr_values[":custom"] = _sanitize_decimal(custom_data)

            try:
                self.table.update_item(
                    Key={"pk": pk, "sk": speaker_id},
                    UpdateExpression=", ".join(update_expr_parts),
                    ExpressionAttributeValues=expr_values,
                )
            except ClientError as e:
                logging.error("create_or_update_speaker: update failed: %s", e)

            existing.last_seen_ts = now
            existing.interaction_count += 1
            if speaker_name:
                existing.speaker_name = speaker_name
            if notes is not None:
                existing.notes = notes
            if preferences is not None:
                existing.preferences = preferences
            if custom_data is not None:
                existing.custom_data = custom_data
            return existing

        else:
            # Create new profile
            item = {
                "pk": pk,
                "sk": speaker_id,
                "item_type": "SPEAKER",
                "agent_id": agent_id,
                "speaker_id": speaker_id,
                "first_seen_ts": now,
                "last_seen_ts": now,
                "interaction_count": 1,
                "enrollment_status": "unknown",
                "gsi1pk": f"SPEAKER#{speaker_id}",
                "gsi1sk": now,
            }

            if speaker_name:
                item["speaker_name"] = speaker_name
            if notes:
                item["notes"] = notes
            if preferences:
                item["preferences"] = _sanitize_decimal(preferences)
            if custom_data:
                item["custom_data"] = _sanitize_decimal(custom_data)

            try:
                self.table.put_item(Item=item)
            except ClientError as e:
                logging.error("create_or_update_speaker: create failed: %s", e)

            return SpeakerProfile(
                speaker_id=speaker_id,
                agent_id=agent_id,
                speaker_name=speaker_name,
                first_seen_ts=now,
                last_seen_ts=now,
                interaction_count=1,
                notes=notes,
                preferences=preferences or {},
                enrollment_status="unknown",
            )

    def update_speaker_profile(
        self,
        agent_id: str,
        speaker_id: str,
        updates: Dict[str, Any],
    ) -> bool:
        """Update specific fields in a speaker profile.

        Args:
            agent_id: Agent identifier
            speaker_id: Speaker identifier
            updates: Dict of field names to new values

        Returns:
            True if update succeeded
        """
        if not self.table or not updates:
            return False

        pk = self._speaker_pk(agent_id)

        # Build update expression
        update_parts = []
        expr_values = {}
        expr_names = {}

        for key, value in updates.items():
            safe_key = key.replace("-", "_")
            placeholder = f":v_{safe_key}"
            name_placeholder = f"#n_{safe_key}"

            update_parts.append(f"{name_placeholder} = {placeholder}")
            expr_values[placeholder] = _sanitize_decimal(value)
            expr_names[name_placeholder] = key

        if not update_parts:
            return False

        try:
            self.table.update_item(
                Key={"pk": pk, "sk": speaker_id},
                UpdateExpression="SET " + ", ".join(update_parts),
                ExpressionAttributeValues=expr_values,
                ExpressionAttributeNames=expr_names,
            )
            return True
        except ClientError as e:
            logging.error("update_speaker_profile: update failed: %s", e)
            return False

    def list_speakers(
        self,
        agent_id: str,
        limit: int = 100,
    ) -> List[SpeakerProfile]:
        """List all speakers for an agent.

        Args:
            agent_id: Agent identifier
            limit: Maximum number of results

        Returns:
            List of SpeakerProfile objects
        """
        if not self.table:
            return []

        pk = self._speaker_pk(agent_id)

        try:
            resp = self.table.query(
                KeyConditionExpression=Key("pk").eq(pk),
                Limit=limit,
            )
            return [SpeakerProfile.from_item(item) for item in resp.get("Items", [])]
        except ClientError as e:
            logging.error("list_speakers: query failed: %s", e)
            return []

    def add_voice_sample(
        self,
        agent_id: str,
        speaker_id: str,
        sample_s3_key: str,
        sample_metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Add a voice sample to a speaker's profile.

        Args:
            agent_id: Agent identifier
            speaker_id: Speaker identifier
            sample_s3_key: S3 key of the voice sample
            sample_metadata: Optional metadata about the sample

        Returns:
            True if sample was added successfully
        """
        if not self.table:
            return False

        pk = self._speaker_pk(agent_id)
        now = _now_iso()

        try:
            # Get current profile
            profile = self.get_speaker_profile(agent_id, speaker_id)
            if not profile:
                # Create profile if doesn't exist
                self.create_or_update_speaker(agent_id, speaker_id)
                profile = self.get_speaker_profile(agent_id, speaker_id)

            # Add sample to list
            samples = profile.voice_samples if profile else []
            if sample_s3_key not in samples:
                samples.append(sample_s3_key)

            # Determine enrollment status
            enrollment_status = "unknown"
            if len(samples) >= self.MIN_SAMPLES_FOR_ENROLLMENT:
                enrollment_status = "enrolled"
            elif samples:
                enrollment_status = "partial"

            # Update profile
            self.table.update_item(
                Key={"pk": pk, "sk": speaker_id},
                UpdateExpression="SET voice_samples = :samples, enrollment_status = :status, last_seen_ts = :now",
                ExpressionAttributeValues={
                    ":samples": samples,
                    ":status": enrollment_status,
                    ":now": now,
                },
            )

            # Also store sample metadata separately for detailed tracking
            if sample_metadata:
                sample_pk = f"VOICE_SAMPLE#{agent_id}"
                sample_sk = sample_s3_key
                sample_item = {
                    "pk": sample_pk,
                    "sk": sample_sk,
                    "item_type": "VOICE_SAMPLE",
                    "agent_id": agent_id,
                    "speaker_id": speaker_id,
                    "s3_key": sample_s3_key,
                    "created_ts": now,
                    "metadata": _sanitize_decimal(sample_metadata),
                }
                self.table.put_item(Item=sample_item)

            logging.info("add_voice_sample: added sample for speaker %s", speaker_id)
            return True

        except ClientError as e:
            logging.error("add_voice_sample: failed: %s", e)
            return False

    def identify_speaker(
        self,
        agent_id: str,
        voice_embedding: Optional[List[float]] = None,
        voice_id: Optional[str] = None,
    ) -> Tuple[Optional[SpeakerProfile], float]:
        """Identify a speaker from voice embedding or ID.

        Args:
            agent_id: Agent identifier
            voice_embedding: Voice embedding vector (optional)
            voice_id: External voice ID (e.g., from Transcribe)

        Returns:
            Tuple of (SpeakerProfile or None, confidence score 0-1)
        """
        # If we have a direct voice_id, look it up
        if voice_id:
            profile = self.get_speaker_profile(agent_id, voice_id)
            if profile:
                return profile, 1.0  # Perfect match by ID

        # TODO: Implement embedding-based matching
        # This would involve:
        # 1. Storing embeddings with speaker profiles
        # 2. Computing cosine similarity with stored embeddings
        # 3. Returning the best match above threshold
        #
        # For now, return no match for embedding-only queries
        if voice_embedding and not voice_id:
            logging.debug("identify_speaker: embedding-based matching not yet implemented")
            return None, 0.0

        return None, 0.0

    def delete_speaker(
        self,
        agent_id: str,
        speaker_id: str,
    ) -> bool:
        """Delete a speaker profile.

        Args:
            agent_id: Agent identifier
            speaker_id: Speaker identifier

        Returns:
            True if deletion succeeded
        """
        if not self.table:
            return False

        pk = self._speaker_pk(agent_id)

        try:
            self.table.delete_item(Key={"pk": pk, "sk": speaker_id})
            logging.info("delete_speaker: deleted %s", speaker_id)
            return True
        except ClientError as e:
            logging.error("delete_speaker: failed: %s", e)
            return False


# Global instance
_registry: Optional[VoiceRegistry] = None


def _get_registry() -> VoiceRegistry:
    global _registry
    if _registry is None:
        _registry = VoiceRegistry()
    return _registry


# Backward-compatible functions

def resolve_voice(
    agent_id: str,
    voice_id: Optional[str] = None,
    claimed_name: Optional[str] = None,
    embedding: Any = None,
) -> Tuple[Optional[str], bool]:
    """Resolve or register speaker identity.

    Returns: (speaker_name_or_None, is_new_voice)

    Backward-compatible wrapper around VoiceRegistry.
    """
    registry = _get_registry()

    if not registry.table:
        logging.error("resolve_voice: DynamoDB table not configured.")
        return claimed_name, False

    if not voice_id:
        return (claimed_name, False) if claimed_name else (None, False)

    vid = str(voice_id)

    # Check if speaker exists
    profile = registry.get_speaker_profile(agent_id, vid)

    if profile:
        # Existing speaker - update interaction
        registry.create_or_update_speaker(
            agent_id, vid,
            speaker_name=claimed_name or profile.speaker_name,
        )
        return (profile.speaker_name or claimed_name, False)

    # New speaker - create profile
    registry.create_or_update_speaker(
        agent_id, vid,
        speaker_name=claimed_name,
    )

    return (claimed_name, True) if claimed_name else (None, True)


def get_speaker_profile(agent_id: str, speaker_id: str) -> Optional[Dict[str, Any]]:
    """Get speaker profile as dict (for tool execution)."""
    registry = _get_registry()
    profile = registry.get_speaker_profile(agent_id, speaker_id)
    return profile.to_dict() if profile else None


def update_speaker_profile(agent_id: str, speaker_id: str, updates: Dict[str, Any]) -> bool:
    """Update speaker profile (for tool execution)."""
    registry = _get_registry()
    return registry.update_speaker_profile(agent_id, speaker_id, updates)
