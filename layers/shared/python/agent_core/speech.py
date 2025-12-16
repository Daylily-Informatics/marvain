from __future__ import annotations

import base64
import logging
import time
from typing import Optional

import boto3


class SpeechSynthesizer:
    """Amazon Polly text-to-speech wrapper.

    If `bucket` is provided, MP3 is saved to S3 and a presigned URL is returned.
    Otherwise, MP3 is returned inline as base64.
    """

    def __init__(
        self,
        voice_id: str = "Matthew",
        region: Optional[str] = None,
        bucket: Optional[str] = None,
        engine: Optional[str] = None,
    ):
        self.voice_id = voice_id or "Matthew"
        self.bucket = bucket or None
        self.engine = engine or None

        if region:
            self.polly = boto3.client("polly", region_name=region)
            self.s3 = boto3.client("s3", region_name=region) if self.bucket else None
        else:
            self.polly = boto3.client("polly")
            self.s3 = boto3.client("s3") if self.bucket else None

    def synthesize(self, text: str, key_prefix: str = "agent-reply") -> Optional[dict]:
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

        # If bucket configured, store to S3
        if self.bucket and self.s3:
            ts = int(time.time())
            key = f"{key_prefix}-{ts}.mp3"
            try:
                self.s3.put_object(Bucket=self.bucket, Key=key, Body=audio_bytes, ContentType="audio/mpeg")
                url = self.s3.generate_presigned_url(
                    ClientMethod="get_object",
                    Params={"Bucket": self.bucket, "Key": key},
                    ExpiresIn=3600,
                )
                return {"url": url, "bucket": self.bucket, "key": key, "content_type": "audio/mpeg"}
            except Exception as e:
                logging.error("SpeechSynthesizer: S3 upload failed, falling back to inline base64: %s", e)

        b64 = base64.b64encode(audio_bytes).decode("utf-8")
        return {"content_type": "audio/mpeg", "data": b64}
