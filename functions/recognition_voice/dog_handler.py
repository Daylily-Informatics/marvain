"""On-demand dog detection and identity embeddings; no training or runtime model downloads."""
from __future__ import annotations

import io
import os

import boto3
import numpy as np
import onnxruntime as ort
from PIL import Image, ImageOps

from agent_hub.dog_identity import MODEL_ID, MODEL_VERSION, DETECTOR_ID, DETECTOR_VERSION

_detector = None
_encoder = None
_mean = np.array([0.485, 0.456, 0.406], dtype=np.float32)
_std = np.array([0.229, 0.224, 0.225], dtype=np.float32)


def tensor(image, size):
    pixels = np.asarray(image.resize((size, size), Image.Resampling.BILINEAR), dtype=np.float32) / 255.0
    return np.transpose((pixels - _mean) / _std, (2, 0, 1))[None].astype(np.float32)


def handler(event, context):
    global _detector, _encoder
    if event["bucket"] != os.environ["ARTIFACT_BUCKET"] or not event["key"].startswith("private-dogs/"):
        raise ValueError("Dog capture is outside the deployment's private dog storage")
    if _detector is None:
        options = ort.SessionOptions()
        options.intra_op_num_threads = 2
        _detector = ort.InferenceSession("/opt/dog-models/detection.onnx", options,
                                        providers=["CPUExecutionProvider"])
        _encoder = ort.InferenceSession("/opt/dog-models/recognition.onnx", options,
                                       providers=["CPUExecutionProvider"])
    response = boto3.client("s3").get_object(Bucket=event["bucket"], Key=event["key"], VersionId=event["version_id"])
    image = ImageOps.exif_transpose(Image.open(io.BytesIO(response["Body"].read()))).convert("RGB")
    boxes, logits = _detector.run(["dets", "labels"], {"input": tensor(image, 384)})
    classes = np.argmax(logits[0], axis=-1)
    probabilities = 1.0 / (1.0 + np.exp(-np.clip(logits[0, :, 18], -80, 80)))
    threshold = float(os.environ["DOG_DETECTION_THRESHOLD"])
    detections = []
    for index in np.flatnonzero((classes == 18) & (probabilities >= threshold)):
        cx, cy, width, height = boxes[0, index].tolist()
        left, top = max(0, int((cx-width/2)*image.width)), max(0, int((cy-height/2)*image.height))
        right, bottom = min(image.width, int((cx+width/2)*image.width)), min(image.height, int((cy+height/2)*image.height))
        if right <= left or bottom <= top:
            continue
        crop = image.crop((left, top, right, bottom))
        embedding = _encoder.run(["embedding"], {"input": tensor(crop, 224)})[0][0]
        detections.append({"box": [left/image.width, top/image.height, right/image.width, bottom/image.height],
                           "detection_score": float(probabilities[index]), "embedding": embedding.tolist()})
    return {"model_id": MODEL_ID, "model_version": MODEL_VERSION,
            "detector_id": DETECTOR_ID, "detector_version": DETECTOR_VERSION, "detections": detections}
