from __future__ import annotations

import base64
import logging
import os
import uuid
from typing import Any, Dict, Optional

import boto3

logger = logging.getLogger(__name__)


class SpeechSynthesizer:
    """Amazon Polly speech synthesis wrapper.

    If bucket is provided, audio is written to S3 and the response includes s3_uri.
    Otherwise, response includes base64-encoded audio bytes.
    """

    def __init__(self, *, bucket: Optional[str] = None, voice_id: str = "Matthew", region: Optional[str] = None):
        self.bucket = bucket
        self.voice_id = voice_id or "Matthew"
        self.region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
        self._polly = boto3.client("polly", region_name=self.region)
        self._s3 = boto3.client("s3", region_name=self.region) if bucket else None

    def synthesize(self, text: str, key_prefix: str = "audio") -> Dict[str, Any]:
        resp = self._polly.synthesize_speech(
            OutputFormat="mp3",
            VoiceId=self.voice_id,
            Text=text,
        )
        audio_bytes = resp["AudioStream"].read()

        if self.bucket and self._s3:
            key = f"{key_prefix.rstrip('/')}/{uuid.uuid4()}.mp3"
            self._s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=audio_bytes,
                ContentType="audio/mpeg",
            )
            return {
                "voice_id": self.voice_id,
                "format": "mp3",
                "s3_bucket": self.bucket,
                "s3_key": key,
                "s3_uri": f"s3://{self.bucket}/{key}",
            }

        return {
            "voice_id": self.voice_id,
            "format": "mp3",
            "audio_base64": base64.b64encode(audio_bytes).decode("utf-8"),
        }
