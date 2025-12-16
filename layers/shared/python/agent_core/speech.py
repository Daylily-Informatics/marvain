from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


# Default retry configuration for S3 operations
S3_RETRY_CONFIG = Config(
    retries={
        "max_attempts": 3,
        "mode": "adaptive",
    }
)


@dataclass
class AudioMetadata:
    """Metadata for stored audio files."""
    key: str
    bucket: str
    content_type: str
    size_bytes: int
    duration_ms: Optional[int] = None
    created_at: Optional[str] = None
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    speaker_id: Optional[str] = None
    transcript: Optional[str] = None
    checksum: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


class S3AudioStore:
    """Manages audio file storage and retrieval from S3.

    Supports:
    - Uploading synthesized audio (TTS output)
    - Uploading recorded audio (user voice)
    - Retrieving audio with presigned URLs
    - Listing audio files by agent/session
    - Audio metadata tracking
    """

    DEFAULT_PRESIGNED_EXPIRY = 3600  # 1 hour
    MAX_PRESIGNED_EXPIRY = 86400  # 24 hours

    def __init__(
        self,
        bucket: str,
        region: Optional[str] = None,
        prefix: str = "audio",
    ):
        self.bucket = bucket
        self.prefix = prefix.rstrip("/")
        self.region = region

        config = S3_RETRY_CONFIG
        if region:
            self.s3 = boto3.client("s3", region_name=region, config=config)
        else:
            self.s3 = boto3.client("s3", config=config)

    def _generate_key(
        self,
        agent_id: str,
        session_id: Optional[str] = None,
        audio_type: str = "tts",
        extension: str = "mp3",
    ) -> str:
        """Generate a unique S3 key for audio storage."""
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        unique_id = uuid.uuid4().hex[:8]

        parts = [self.prefix, agent_id]
        if session_id:
            parts.append(session_id)
        parts.append(audio_type)
        parts.append(f"{timestamp}-{unique_id}.{extension}")

        return "/".join(parts)

    def _compute_checksum(self, data: bytes) -> str:
        """Compute MD5 checksum for data integrity verification."""
        return hashlib.md5(data).hexdigest()

    def upload_audio(
        self,
        audio_bytes: bytes,
        agent_id: str,
        session_id: Optional[str] = None,
        speaker_id: Optional[str] = None,
        audio_type: str = "tts",
        content_type: str = "audio/mpeg",
        transcript: Optional[str] = None,
        custom_metadata: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, AudioMetadata]:
        """Upload audio bytes to S3 with metadata.

        Args:
            audio_bytes: Raw audio data
            agent_id: Agent identifier
            session_id: Optional session identifier
            speaker_id: Optional speaker identifier (for recorded audio)
            audio_type: Type of audio ('tts' for synthesized, 'recording' for user voice)
            content_type: MIME type of the audio
            transcript: Optional transcript of the audio content
            custom_metadata: Additional metadata to store

        Returns:
            Tuple of (presigned_url, AudioMetadata)

        Raises:
            Exception if upload fails after retries
        """
        extension = "mp3" if "mpeg" in content_type else content_type.split("/")[-1]
        key = self._generate_key(agent_id, session_id, audio_type, extension)
        checksum = self._compute_checksum(audio_bytes)
        created_at = datetime.utcnow().isoformat() + "Z"

        # Build S3 metadata (all values must be strings)
        s3_metadata = {
            "agent-id": agent_id,
            "audio-type": audio_type,
            "created-at": created_at,
            "checksum": checksum,
        }
        if session_id:
            s3_metadata["session-id"] = session_id
        if speaker_id:
            s3_metadata["speaker-id"] = speaker_id
        if transcript:
            # Truncate transcript for metadata (S3 has 2KB limit)
            s3_metadata["transcript"] = transcript[:500] if len(transcript) > 500 else transcript
        if custom_metadata:
            for k, v in custom_metadata.items():
                s3_metadata[k.lower().replace("_", "-")] = str(v)[:500]

        try:
            self.s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=audio_bytes,
                ContentType=content_type,
                Metadata=s3_metadata,
            )
            logging.info("S3AudioStore: uploaded %s to s3://%s/%s", audio_type, self.bucket, key)
        except ClientError as e:
            logging.error("S3AudioStore: upload failed: %s", e)
            raise

        # Generate presigned URL
        url = self.get_presigned_url(key)

        metadata = AudioMetadata(
            key=key,
            bucket=self.bucket,
            content_type=content_type,
            size_bytes=len(audio_bytes),
            created_at=created_at,
            agent_id=agent_id,
            session_id=session_id,
            speaker_id=speaker_id,
            transcript=transcript,
            checksum=checksum,
        )

        return url, metadata

    def get_presigned_url(
        self,
        key: str,
        expiry_seconds: int = DEFAULT_PRESIGNED_EXPIRY,
    ) -> str:
        """Generate a presigned URL for downloading audio.

        Args:
            key: S3 object key
            expiry_seconds: URL expiration time in seconds

        Returns:
            Presigned URL string
        """
        expiry = min(expiry_seconds, self.MAX_PRESIGNED_EXPIRY)
        try:
            url = self.s3.generate_presigned_url(
                ClientMethod="get_object",
                Params={"Bucket": self.bucket, "Key": key},
                ExpiresIn=expiry,
            )
            return url
        except ClientError as e:
            logging.error("S3AudioStore: presigned URL generation failed: %s", e)
            raise

    def download_audio(self, key: str) -> Tuple[bytes, Dict[str, str]]:
        """Download audio bytes and metadata from S3.

        Args:
            key: S3 object key

        Returns:
            Tuple of (audio_bytes, metadata_dict)
        """
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=key)
            audio_bytes = response["Body"].read()
            metadata = response.get("Metadata", {})
            return audio_bytes, metadata
        except ClientError as e:
            logging.error("S3AudioStore: download failed for %s: %s", key, e)
            raise

    def list_audio_files(
        self,
        agent_id: str,
        session_id: Optional[str] = None,
        audio_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List audio files for an agent/session.

        Args:
            agent_id: Agent identifier
            session_id: Optional session filter
            audio_type: Optional type filter ('tts' or 'recording')
            limit: Maximum number of results

        Returns:
            List of audio file metadata dicts
        """
        prefix_parts = [self.prefix, agent_id]
        if session_id:
            prefix_parts.append(session_id)
        if audio_type:
            prefix_parts.append(audio_type)

        prefix = "/".join(prefix_parts)

        try:
            paginator = self.s3.get_paginator("list_objects_v2")
            results = []

            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix, MaxKeys=limit):
                for obj in page.get("Contents", []):
                    results.append({
                        "key": obj["Key"],
                        "size": obj["Size"],
                        "last_modified": obj["LastModified"].isoformat(),
                    })
                    if len(results) >= limit:
                        break
                if len(results) >= limit:
                    break

            return results
        except ClientError as e:
            logging.error("S3AudioStore: list failed: %s", e)
            return []

    def delete_audio(self, key: str) -> bool:
        """Delete an audio file from S3.

        Args:
            key: S3 object key

        Returns:
            True if deletion succeeded
        """
        try:
            self.s3.delete_object(Bucket=self.bucket, Key=key)
            logging.info("S3AudioStore: deleted s3://%s/%s", self.bucket, key)
            return True
        except ClientError as e:
            logging.error("S3AudioStore: delete failed for %s: %s", key, e)
            return False

    def get_audio_metadata(self, key: str) -> Optional[AudioMetadata]:
        """Get metadata for an audio file without downloading the content.

        Args:
            key: S3 object key

        Returns:
            AudioMetadata or None if not found
        """
        try:
            response = self.s3.head_object(Bucket=self.bucket, Key=key)
            s3_meta = response.get("Metadata", {})

            return AudioMetadata(
                key=key,
                bucket=self.bucket,
                content_type=response.get("ContentType", "audio/mpeg"),
                size_bytes=response.get("ContentLength", 0),
                created_at=s3_meta.get("created-at"),
                agent_id=s3_meta.get("agent-id"),
                session_id=s3_meta.get("session-id"),
                speaker_id=s3_meta.get("speaker-id"),
                transcript=s3_meta.get("transcript"),
                checksum=s3_meta.get("checksum"),
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "404":
                return None
            logging.error("S3AudioStore: head_object failed for %s: %s", key, e)
            return None


class SpeechSynthesizer:
    """Amazon Polly text-to-speech wrapper with S3 integration.

    If `bucket` is provided, MP3 is saved to S3 and a presigned URL is returned.
    Otherwise, MP3 is returned inline as base64.
    """

    def __init__(
        self,
        voice_id: str = "Matthew",
        region: Optional[str] = None,
        bucket: Optional[str] = None,
        engine: Optional[str] = None,
        audio_store: Optional[S3AudioStore] = None,
    ):
        self.voice_id = voice_id or "Matthew"
        self.bucket = bucket or None
        self.engine = engine or None
        self.region = region

        if region:
            self.polly = boto3.client("polly", region_name=region)
        else:
            self.polly = boto3.client("polly")

        # Use provided audio store or create one if bucket is configured
        if audio_store:
            self.audio_store = audio_store
        elif self.bucket:
            self.audio_store = S3AudioStore(bucket=self.bucket, region=region)
        else:
            self.audio_store = None

    def synthesize(
        self,
        text: str,
        key_prefix: str = "agent-reply",
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Optional[dict]:
        """Synthesize speech from text.

        Args:
            text: Text to synthesize
            key_prefix: S3 key prefix (deprecated, use agent_id/session_id instead)
            agent_id: Agent identifier for S3 storage
            session_id: Session identifier for S3 storage

        Returns:
            Dict with audio data (URL or base64) and metadata
        """
        if not text or not text.strip():
            return None

        try:
            synth_kwargs = {"Text": text, "VoiceId": self.voice_id, "OutputFormat": "mp3"}
            if self.engine:
                synth_kwargs["Engine"] = self.engine
            resp = self.polly.synthesize_speech(**synth_kwargs)
        except Exception as e:
            logging.error("SpeechSynthesizer: Polly synthesize failed: %s", e)
            return None

        stream = resp.get("AudioStream")
        if not stream:
            logging.error("SpeechSynthesizer: Polly returned no AudioStream")
            return None

        audio_bytes = stream.read()

        # If audio store is configured, use it for S3 storage
        if self.audio_store:
            try:
                # Extract agent_id from key_prefix for backward compatibility
                if not agent_id and "/" in key_prefix:
                    agent_id = key_prefix.split("/")[0]
                agent_id = agent_id or "default-agent"

                url, metadata = self.audio_store.upload_audio(
                    audio_bytes=audio_bytes,
                    agent_id=agent_id,
                    session_id=session_id,
                    audio_type="tts",
                    content_type="audio/mpeg",
                    transcript=text[:500] if text else None,
                )
                return {
                    "url": url,
                    "bucket": metadata.bucket,
                    "key": metadata.key,
                    "content_type": metadata.content_type,
                    "size_bytes": metadata.size_bytes,
                    "checksum": metadata.checksum,
                }
            except Exception as e:
                logging.error("SpeechSynthesizer: S3 upload failed, falling back to inline base64: %s", e)

        # Fallback to base64 inline
        b64 = base64.b64encode(audio_bytes).decode("utf-8")
        return {"content_type": "audio/mpeg", "data": b64}


class AudioRecorder:
    """Handles recording and storage of user audio.

    This class is used for voice enrollment and conversation recording.
    """

    def __init__(
        self,
        audio_store: S3AudioStore,
        agent_id: str,
    ):
        self.audio_store = audio_store
        self.agent_id = agent_id

    def store_recording(
        self,
        audio_bytes: bytes,
        session_id: Optional[str] = None,
        speaker_id: Optional[str] = None,
        transcript: Optional[str] = None,
        content_type: str = "audio/wav",
    ) -> Tuple[str, AudioMetadata]:
        """Store a user audio recording.

        Args:
            audio_bytes: Raw audio data
            session_id: Session identifier
            speaker_id: Speaker identifier
            transcript: Transcript of the audio
            content_type: MIME type

        Returns:
            Tuple of (presigned_url, AudioMetadata)
        """
        return self.audio_store.upload_audio(
            audio_bytes=audio_bytes,
            agent_id=self.agent_id,
            session_id=session_id,
            speaker_id=speaker_id,
            audio_type="recording",
            content_type=content_type,
            transcript=transcript,
        )

    def get_recording(self, key: str) -> Tuple[bytes, Dict[str, str]]:
        """Retrieve a stored recording.

        Args:
            key: S3 object key

        Returns:
            Tuple of (audio_bytes, metadata_dict)
        """
        return self.audio_store.download_audio(key)

    def list_recordings(
        self,
        session_id: Optional[str] = None,
        speaker_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List recordings for this agent.

        Args:
            session_id: Optional session filter
            speaker_id: Optional speaker filter (requires fetching metadata)
            limit: Maximum results

        Returns:
            List of recording metadata
        """
        recordings = self.audio_store.list_audio_files(
            agent_id=self.agent_id,
            session_id=session_id,
            audio_type="recording",
            limit=limit if not speaker_id else limit * 3,
        )

        # Filter by speaker_id if requested
        if speaker_id:
            filtered = []
            for rec in recordings:
                meta = self.audio_store.get_audio_metadata(rec["key"])
                if meta and meta.speaker_id == speaker_id:
                    filtered.append({**rec, "metadata": meta.to_dict()})
                if len(filtered) >= limit:
                    break
            return filtered

        return recordings
