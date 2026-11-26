from __future__ import annotations

import io
import struct

import numpy as np
from PIL import Image

MAGIC = b"SHSG1"


def embed_payload(image_bytes: bytes, payload: bytes) -> bytes:
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    array = np.array(image, dtype=np.uint8)
    packed = MAGIC + struct.pack(">I", len(payload)) + payload
    bits = np.unpackbits(np.frombuffer(packed, dtype=np.uint8))
    flat = array.reshape(-1)
    if bits.size > flat.size:
        max_bytes = max(0, (flat.size // 8) - len(MAGIC) - 4)
        raise ValueError(f"Pesan terlalu besar untuk gambar ini. Perkiraan kapasitas {max_bytes} byte.")
    flat[: bits.size] = (flat[: bits.size] & 0xFE) | bits
    out = io.BytesIO()
    Image.fromarray(array, mode="RGB").save(out, format="PNG")
    return out.getvalue()


def extract_payload(image_bytes: bytes) -> bytes:
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    flat = np.asarray(image, dtype=np.uint8).reshape(-1)
    header_bits = flat[: (len(MAGIC) + 4) * 8] & 1
    header = np.packbits(header_bits).tobytes()
    if not header.startswith(MAGIC):
        raise ValueError("Tidak ditemukan pesan SecureHub pada gambar ini.")
    length = struct.unpack(">I", header[len(MAGIC):len(MAGIC) + 4])[0]
    total_bits = (len(MAGIC) + 4 + length) * 8
    if total_bits > flat.size:
        raise ValueError("Data tersembunyi tidak lengkap atau gambar rusak.")
    data_bits = flat[(len(MAGIC) + 4) * 8:total_bits] & 1
    return np.packbits(data_bits).tobytes()
