from __future__ import annotations

import os
import tempfile
from pathlib import Path

import cv2
import numpy as np
from PIL import Image

FACE_SIZE = (200, 200)
FACE_CONFIDENCE_LIMIT = 78.0  # Lower LBPH confidence is a closer match.


def _detect_face(image_bytes: bytes) -> np.ndarray:
    image = Image.open(__import__("io").BytesIO(image_bytes)).convert("RGB")
    rgb = np.asarray(image)
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    cascade_path = Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml"
    detector = cv2.CascadeClassifier(str(cascade_path))
    if detector.empty():
        raise RuntimeError("Model deteksi wajah OpenCV tidak dapat dimuat.")
    faces = detector.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(70, 70))
    if len(faces) == 0:
        raise ValueError("Wajah tidak terdeteksi. Hadapkan wajah ke kamera dengan pencahayaan cukup.")
    x, y, w, h = max(faces, key=lambda item: item[2] * item[3])
    # Slightly pad the crop so the face edges are not cut off.
    pad_x, pad_y = int(w * 0.12), int(h * 0.12)
    x1, y1 = max(0, x - pad_x), max(0, y - pad_y)
    x2, y2 = min(gray.shape[1], x + w + pad_x), min(gray.shape[0], y + h + pad_y)
    face = gray[y1:y2, x1:x2]
    face = cv2.resize(face, FACE_SIZE, interpolation=cv2.INTER_AREA)
    return cv2.equalizeHist(face)


def extract_face_sample(image_bytes: bytes) -> np.ndarray:
    return _detect_face(image_bytes)


def train_face_model(samples: list[np.ndarray]) -> bytes:
    if len(samples) < 3:
        raise ValueError("Minimal tiga sampel wajah diperlukan.")
    if not hasattr(cv2, "face") or not hasattr(cv2.face, "LBPHFaceRecognizer_create"):
        raise RuntimeError("OpenCV contrib belum terpasang. Jalankan: pip install opencv-contrib-python-headless")
    recognizer = cv2.face.LBPHFaceRecognizer_create(radius=1, neighbors=8, grid_x=8, grid_y=8)
    recognizer.train(samples, np.zeros(len(samples), dtype=np.int32))
    with tempfile.TemporaryDirectory() as tmp:
        model_path = Path(tmp) / "face_model.yml"
        recognizer.write(str(model_path))
        return model_path.read_bytes()


def verify_face(image_bytes: bytes, model_bytes: bytes) -> tuple[bool, float, str]:
    face = _detect_face(image_bytes)
    if not hasattr(cv2, "face"):
        return False, 999.0, "OpenCV contrib tidak tersedia."
    with tempfile.TemporaryDirectory() as tmp:
        model_path = Path(tmp) / "face_model.yml"
        model_path.write_bytes(model_bytes)
        recognizer = cv2.face.LBPHFaceRecognizer_create()
        recognizer.read(str(model_path))
        label, confidence = recognizer.predict(face)
    matched = label == 0 and confidence <= FACE_CONFIDENCE_LIMIT
    return matched, float(confidence), "Wajah cocok." if matched else "Wajah tidak cocok dengan data biometrik."
