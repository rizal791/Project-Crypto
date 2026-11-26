from __future__ import annotations

import base64
import json
import os
import struct
import uuid
from datetime import datetime
from pathlib import Path

import streamlit as st

from securehub import blockchain, db
from securehub.biometric import extract_face_sample, train_face_model, verify_face
from securehub.crypto_utils import (
    create_user_crypto,
    decrypt_biometric_model,
    decrypt_file,
    decrypt_note,
    decrypt_super_text,
    encrypt_biometric_model,
    encrypt_file,
    encrypt_note,
    encrypt_super_text,
    load_public_key,
    unlock_private_key,
    utc_now,
    verify_password,
)
from securehub.dongle import create_dongle_file, find_connected_dongle, removable_mounts
from securehub.steganography import embed_payload, extract_payload

APP_TITLE = "SecureHub"
MAX_FILE_SIZE = 10 * 1024 * 1024

st.set_page_config(page_title="SecureHub | Pesan Aman", page_icon="🔐", layout="wide")
st.markdown(
    """
    <style>
      .block-container {max-width: 1200px; padding-top: 1.7rem; padding-bottom: 3rem;}
      .hero {padding: 1.35rem 1.5rem; border-radius: 16px; background: linear-gradient(120deg,#102a43,#164e63); color:#fff; margin-bottom:1rem;}
      .hero h1 {color:#fff; margin:0 0 .25rem 0; font-size:2rem;}
      .hero p {color:#d9eaf3; margin:0;}
      .small-muted {color:#6b7280; font-size:.88rem;}
      div[data-testid="stMetric"] {background:rgba(128,128,128,.07); padding:12px; border-radius:12px;}
      .stButton>button {border-radius:9px;}
    </style>
    """,
    unsafe_allow_html=True,
)


def init_session() -> None:
    defaults = {
        "logged_in": False,
        "current_user": None,
        "private_key": None,
        "pending_enroll_username": None,
        "pending_enroll_password": None,
        "pending_first_admin": False,
        "face_samples": [],
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def hero() -> None:
    st.markdown(
        '<div class="hero"><h1>🔐 SecureHub</h1><p>Platform komunikasi digital dengan keamanan berlapis.</p></div>',
        unsafe_allow_html=True,
    )


def clear_login() -> None:
    st.session_state.logged_in = False
    st.session_state.current_user = None
    st.session_state.private_key = None


def begin_face_enrollment(username: str, password: str, first_admin: bool) -> None:
    st.session_state.pending_enroll_username = username
    st.session_state.pending_enroll_password = password
    st.session_state.pending_first_admin = first_admin
    st.session_state.face_samples = []


def render_first_setup() -> None:
    hero()
    st.title("Pengaturan awal SecureHub")
    st.write("Buat akun administrator, daftarkan USB sebagai dongle, lalu daftarkan wajah melalui webcam.")
    st.info("USB hanya digunakan sebagai kunci perangkat (dongle). Foto biometrik tidak diambil dari USB atau file komputer; pendaftaran wajah dilakukan langsung melalui webcam browser.")
    with st.form("initial_setup_form"):
        username = st.text_input("Username administrator", placeholder="contoh: admin")
        password = st.text_input("Password", type="password", help="Gunakan minimal 10 karakter.")
        confirm = st.text_input("Konfirmasi password", type="password")
        usb_path = st.text_input("Lokasi USB", placeholder="Windows: E:\\  |  Linux: /media/user/USB")
        submitted = st.form_submit_button("Buat akun dan daftarkan USB", type="primary", use_container_width=True)
    if submitted:
        username = username.strip()
        if len(username) < 3 or not username.replace("_", "").isalnum():
            st.error("Username minimal 3 karakter dan hanya boleh berisi huruf, angka, atau underscore.")
        elif len(password) < 10:
            st.error("Password minimal 10 karakter.")
        elif password != confirm:
            st.error("Konfirmasi password tidak sama.")
        elif not usb_path.strip():
            st.error("Masukkan lokasi USB terlebih dahulu.")
        else:
            try:
                _, dongle_hash = create_dongle_file(usb_path.strip())
                keys = create_user_crypto(password, username)
                db.insert_user({
                    "username": username,
                    **keys,
                    "role": "admin",
                    "created_at": utc_now(),
                })
                db.set_setting("dongle_hash", dongle_hash)
                begin_face_enrollment(username, password, True)
                st.success("Akun dibuat dan dongle terdaftar. Lanjutkan pendaftaran wajah.")
                st.rerun()
            except FileExistsError:
                st.error("Username sudah digunakan.")
            except Exception as exc:
                st.error(f"Pengaturan awal gagal: {exc}")


def render_face_enrollment() -> None:
    username = st.session_state.pending_enroll_username
    password = st.session_state.pending_enroll_password
    first_admin = st.session_state.pending_first_admin
    hero()
    st.title("Pendaftaran biometrik wajah")
    st.write(f"Akun: **{username}**")
    st.markdown(
        "Gunakan webcam laptop/PC yang muncul di bawah untuk mengambil minimal **3 sampel wajah** dengan sedikit perubahan sudut. Lepas kacamata gelap, pastikan wajah terlihat jelas, dan gunakan pencahayaan yang cukup."
    )
    st.info("Sumber biometrik: webcam melalui browser. Jangan pilih atau menyalin foto ke flashdisk; SecureHub tidak menggunakan file foto dari USB untuk pendaftaran wajah.")
    camera = st.camera_input("Webcam — ambil sampel wajah", key=f"face_camera_{username}")
    c1, c2 = st.columns([1, 2])
    with c1:
        if st.button("Tambahkan sampel", use_container_width=True, disabled=camera is None):
            try:
                face = extract_face_sample(camera.getvalue())
                if len(st.session_state.face_samples) >= 8:
                    st.warning("Maksimal 8 sampel. Simpan model wajah sekarang.")
                else:
                    st.session_state.face_samples.append(face)
                    st.success(f"Sampel berhasil ditambahkan ({len(st.session_state.face_samples)}).")
            except Exception as exc:
                st.error(str(exc))
    with c2:
        st.metric("Sampel wajah tersimpan", len(st.session_state.face_samples), "Minimal 3")
    if st.session_state.face_samples:
        st.caption("Sampel berada sementara di memori sesi dan tidak disimpan sebagai foto mentah.")
    can_save = len(st.session_state.face_samples) >= 3
    if st.button("Simpan biometrik dan lanjutkan", type="primary", use_container_width=True, disabled=not can_save):
        try:
            model_bytes = train_face_model(st.session_state.face_samples)
            user = db.get_user(username)
            nonce, encrypted_model = encrypt_biometric_model(model_bytes, password, user["key_salt"], username)
            db.save_face_model(username, nonce, encrypted_model)
            st.session_state.pending_enroll_username = None
            st.session_state.pending_enroll_password = None
            st.session_state.face_samples = []
            if first_admin:
                user = db.get_user(username)
                st.session_state.private_key = unlock_private_key(user, password)
                st.session_state.current_user = username
                st.session_state.logged_in = True
            st.success("Biometrik berhasil didaftarkan.")
            st.rerun()
        except Exception as exc:
            st.error(f"Gagal menyimpan biometrik: {exc}")
    if not first_admin and st.button("Batalkan pendaftaran pengguna"):
        st.session_state.pending_enroll_username = None
        st.session_state.pending_enroll_password = None
        st.session_state.face_samples = []
        st.rerun()


def render_login() -> None:
    hero()
    left, right = st.columns([1.05, 1])
    with left:
        st.subheader("Masuk ke SecureHub")
        st.write("Login membutuhkan password, USB dongle terdaftar, dan verifikasi wajah langsung melalui webcam.")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        st.info("USB berfungsi sebagai dongle perangkat. Untuk biometrik, izinkan akses kamera pada browser lalu ambil gambar wajah dari webcam di bawah ini.")
        camera = st.camera_input("Webcam — ambil gambar untuk verifikasi wajah", key="login_face_camera")
        if st.button("Login", type="primary", use_container_width=True):
            user = db.get_user(username.strip()) if username.strip() else None
            if not user or not verify_password(password, user["password_salt"], user["password_hash"]):
                st.error("Username atau password salah.")
            else:
                dongle_ok, dongle_message = find_connected_dongle(db.get_setting("dongle_hash"))
                if not dongle_ok:
                    st.error(dongle_message)
                elif not user["face_enc"] or not user["face_nonce"]:
                    st.error("Biometrik akun belum didaftarkan. Hubungi administrator.")
                elif camera is None:
                    st.error("Aktifkan webcam dan ambil gambar wajah terlebih dahulu.")
                else:
                    try:
                        model = decrypt_biometric_model(
                            user["face_nonce"], user["face_enc"], password, user["key_salt"], user["username"]
                        )
                        matched, confidence, message = verify_face(camera.getvalue(), model)
                        if not matched:
                            st.error(f"{message} (nilai kecocokan: {confidence:.1f})")
                        else:
                            st.session_state.private_key = unlock_private_key(user, password)
                            st.session_state.current_user = user["username"]
                            st.session_state.logged_in = True
                            st.success("Verifikasi berhasil. Selamat datang!")
                            st.rerun()
                    except Exception as exc:
                        st.error(f"Verifikasi biometrik gagal: {exc}")
    with right:
        st.subheader("Status perangkat")
        dongle_ok, dongle_message = find_connected_dongle(db.get_setting("dongle_hash"))
        if dongle_ok:
            st.success(dongle_message)
        else:
            st.warning(dongle_message)
        with st.expander("USB yang terdeteksi"):
            mounts = removable_mounts()
            if mounts:
                for mount in mounts:
                    st.code(str(mount))
            else:
                st.caption("Belum ada drive removable yang terdeteksi.")
        st.markdown("**Tiga lapisan akses:**")
        st.markdown("1. Password akun (PBKDF2-HMAC-SHA256).\n2. USB dongle yang terdaftar (token perangkat, bukan foto).\n3. Pencocokan sampel wajah yang diambil langsung dari webcam browser (LBPH).")
        st.caption("Biometrik demo tidak memiliki liveness detection dan tidak setara dengan Windows Hello/Face ID.")
        incomplete_users = [name for name in db.list_users() if not db.get_user(name)["face_enc"]]
        if incomplete_users:
            with st.expander("Lanjutkan pendaftaran biometrik"):
                st.caption("Gunakan bagian ini bila pendaftaran wajah sebelumnya terputus.")
                pending_name = st.selectbox("Akun", incomplete_users, key="login_pending_face_user")
                pending_password = st.text_input("Password akun", type="password", key="login_pending_face_password")
                if st.button("Lanjutkan pendaftaran wajah", key="login_resume_face", use_container_width=True):
                    pending_user = db.get_user(pending_name)
                    connected, detail = find_connected_dongle(db.get_setting("dongle_hash"))
                    if not connected:
                        st.error(detail)
                    elif not verify_password(pending_password, pending_user["password_salt"], pending_user["password_hash"]):
                        st.error("Password akun tidak sesuai.")
                    else:
                        begin_face_enrollment(pending_name, pending_password, pending_user["role"] == "admin")
                        st.rerun()


def _json_file_plaintext(filename: str, media_type: str, data: bytes) -> bytes:
    metadata = json.dumps({"filename": filename, "media_type": media_type}, ensure_ascii=False).encode("utf-8")
    return struct.pack(">I", len(metadata)) + metadata + data


def _parse_file_plaintext(data: bytes) -> tuple[str, str, bytes]:
    if len(data) < 4:
        raise ValueError("Format file terenkripsi tidak valid.")
    meta_len = struct.unpack(">I", data[:4])[0]
    if meta_len > len(data) - 4:
        raise ValueError("Metadata file rusak.")
    metadata = json.loads(data[4:4 + meta_len].decode("utf-8"))
    return metadata["filename"], metadata.get("media_type", "application/octet-stream"), data[4 + meta_len:]


def _decode_message(row: dict, current_user: str) -> dict:
    role = "sender" if row["sender"].lower() == current_user.lower() else "recipient"
    plain = decrypt_super_text(
        {"nonce": row["nonce"], "ciphertext": row["ciphertext"],
         "wrapped_sender": row["wrapped_sender"], "wrapped_recipient": row["wrapped_recipient"]},
        st.session_state.private_key, role,
    )
    return json.loads(plain)


def render_messages(username: str) -> None:
    st.subheader("Pesan terenkripsi")
    users = db.list_users()
    with st.form("send_message_form"):
        c1, c2 = st.columns([1, 1])
        with c1:
            recipient = st.selectbox("Penerima", users, index=0 if users else None)
        with c2:
            subject = st.text_input("Subjek", max_chars=100)
        body = st.text_area("Isi pesan", height=130, placeholder="Tulis pesan yang ingin dikirim...")
        send = st.form_submit_button("Enkripsi dan kirim pesan", type="primary", use_container_width=True)
    if send:
        if not body.strip():
            st.error("Isi pesan tidak boleh kosong.")
        else:
            receiver = db.get_user(recipient)
            sender = db.get_user(username)
            content = json.dumps({"subject": subject.strip() or "Tanpa subjek", "body": body}, ensure_ascii=False)
            envelope = encrypt_super_text(content, sender["public_key"], receiver["public_key"])
            db.insert_message({
                "id": str(uuid.uuid4()), "sender": username, "recipient": recipient,
                "created_at": utc_now(), **envelope,
            })
            st.success(f"Pesan berhasil dienkripsi dan dikirim kepada {recipient}.")
    st.divider()
    inbox_tab, sent_tab = st.tabs(["Kotak masuk", "Pesan terkirim"])
    with inbox_tab:
        messages = db.get_messages(username, "inbox")
        if not messages:
            st.info("Belum ada pesan masuk.")
        for row in messages:
            with st.expander(f"Dari {row['sender']}  ·  {row['created_at']}"):
                try:
                    decoded = _decode_message(row, username)
                    st.markdown(f"**{decoded.get('subject', 'Pesan')}**")
                    st.write(decoded.get("body", ""))
                except Exception:
                    st.error("Pesan tidak dapat didekripsi. Kunci atau data mungkin tidak cocok.")
    with sent_tab:
        messages = db.get_messages(username, "sent")
        if not messages:
            st.info("Belum ada pesan terkirim.")
        for row in messages:
            with st.expander(f"Kepada {row['recipient']}  ·  {row['created_at']}"):
                try:
                    decoded = _decode_message(row, username)
                    st.markdown(f"**{decoded.get('subject', 'Pesan')}**")
                    st.write(decoded.get("body", ""))
                except Exception:
                    st.error("Pesan tidak dapat didekripsi.")


def render_files(username: str) -> None:
    st.subheader("Enkripsi dan pengiriman file")
    st.caption("File dienkripsi langsung dengan AES-256-GCM. Nama file dan tipe MIME disimpan di dalam payload terenkripsi.")
    users = db.list_users()
    with st.form("send_file_form"):
        recipient = st.selectbox("Penerima file", users, key="file_recipient")
        uploaded = st.file_uploader("Pilih file (maksimal 10 MB)", key="file_upload")
        send = st.form_submit_button("Enkripsi dan kirim file", type="primary", use_container_width=True)
    if send:
        if uploaded is None:
            st.error("Pilih file terlebih dahulu.")
        elif uploaded.size > MAX_FILE_SIZE:
            st.error("Ukuran file melebihi batas 10 MB.")
        else:
            sender_user = db.get_user(username)
            receiver_user = db.get_user(recipient)
            packed = _json_file_plaintext(uploaded.name, uploaded.type or "application/octet-stream", uploaded.getvalue())
            envelope = encrypt_file(packed, sender_user["public_key"], receiver_user["public_key"])
            file_id = str(uuid.uuid4())
            db.insert_file({
                "id": file_id, "sender": username, "recipient": recipient,
                "filename": f"securehub-{file_id}.bin", "media_type": "application/octet-stream",
                "created_at": utc_now(), **envelope,
            })
            st.success(f"File berhasil dienkripsi dan dikirim kepada {recipient}.")
    st.divider()
    incoming, outgoing = st.tabs(["File diterima", "File terkirim"])
    with incoming:
        rows = db.get_files(username, "inbox")
        if not rows:
            st.info("Belum ada file diterima.")
        for row in rows:
            with st.container(border=True):
                st.write(f"**Dari:** {row['sender']}  |  **Tanggal:** {row['created_at']}")
                try:
                    packed = decrypt_file(
                        {"nonce": row["nonce"], "ciphertext": row["ciphertext"],
                         "wrapped_sender": row["wrapped_sender"], "wrapped_recipient": row["wrapped_recipient"]},
                        st.session_state.private_key, "recipient"
                    )
                    filename, media_type, raw = _parse_file_plaintext(packed)
                    st.write(f"File: `{filename}` ({len(raw):,} byte)")
                    st.download_button(
                        "Unduh dan dekripsi", data=raw, file_name=Path(filename).name,
                        mime=media_type, key=f"download_in_{row['id']}", use_container_width=True
                    )
                except Exception as exc:
                    st.error(f"File gagal didekripsi: {exc}")
    with outgoing:
        rows = db.get_files(username, "sent")
        if not rows:
            st.info("Belum ada file terkirim.")
        for row in rows:
            with st.container(border=True):
                st.write(f"**Kepada:** {row['recipient']}  |  **Tanggal:** {row['created_at']}")
                try:
                    packed = decrypt_file(
                        {"nonce": row["nonce"], "ciphertext": row["ciphertext"],
                         "wrapped_sender": row["wrapped_sender"], "wrapped_recipient": row["wrapped_recipient"]},
                        st.session_state.private_key, "sender"
                    )
                    filename, media_type, raw = _parse_file_plaintext(packed)
                    st.write(f"File: `{filename}` ({len(raw):,} byte)")
                    st.download_button(
                        "Unduh salinan", data=raw, file_name=Path(filename).name, mime=media_type,
                        key=f"download_out_{row['id']}", use_container_width=True
                    )
                except Exception:
                    st.error("Salinan file tidak dapat didekripsi.")


def render_notes(username: str) -> None:
    st.subheader("Penyimpanan pesan penting")
    st.caption("Catatan dienkripsi dengan AES-GCM dan kuncinya dibungkus oleh RSA akun sendiri sebelum masuk SQLite.")
    with st.form("save_note_form"):
        title = st.text_input("Judul catatan")
        body = st.text_area("Isi catatan", height=120)
        save = st.form_submit_button("Enkripsi dan simpan", type="primary", use_container_width=True)
    if save:
        if not title.strip() or not body.strip():
            st.error("Judul dan isi catatan wajib diisi.")
        else:
            user = db.get_user(username)
            envelope = encrypt_note(json.dumps({"title": title, "body": body}, ensure_ascii=False), user["public_key"])
            db.insert_note({"id": str(uuid.uuid4()), "owner": username, "created_at": utc_now(), **envelope})
            st.success("Catatan telah dienkripsi dan disimpan ke database.")
    st.divider()
    notes = db.get_notes(username)
    if not notes:
        st.info("Belum ada catatan tersimpan.")
    for row in notes:
        with st.expander(f"Catatan terenkripsi · {row['created_at']}"):
            try:
                decoded = json.loads(decrypt_note(
                    {"nonce": row["nonce"], "ciphertext": row["ciphertext"], "wrapped_key": row["wrapped_key"]},
                    st.session_state.private_key,
                ))
                st.markdown(f"**{decoded['title']}**")
                st.write(decoded["body"])
            except Exception:
                st.error("Catatan tidak dapat didekripsi.")


def _pack_stego_envelope(envelope: dict[str, bytes], sender: str, recipient: str) -> bytes:
    result = {
        "version": 1, "sender": sender, "recipient": recipient, "created_at": utc_now(),
        "nonce": base64.b64encode(envelope["nonce"]).decode("ascii"),
        "ciphertext": base64.b64encode(envelope["ciphertext"]).decode("ascii"),
        "wrapped_sender": base64.b64encode(envelope["wrapped_sender"]).decode("ascii"),
        "wrapped_recipient": base64.b64encode(envelope["wrapped_recipient"]).decode("ascii"),
    }
    return json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _unpack_stego_envelope(payload: bytes) -> dict:
    obj = json.loads(payload.decode("utf-8"))
    if obj.get("version") != 1:
        raise ValueError("Versi pesan tersembunyi tidak didukung.")
    for key in ("nonce", "ciphertext", "wrapped_sender", "wrapped_recipient"):
        obj[key] = base64.b64decode(obj[key])
    return obj


def render_steganography(username: str) -> None:
    st.subheader("Steganografi gambar")
    st.caption("Pesan terlebih dahulu dienkripsi (Vigenère + AES-GCM), kemudian disisipkan ke bit terakhir kanal warna gambar (LSB).")
    embed_tab, extract_tab = st.tabs(["Sisipkan pesan", "Ekstrak pesan"])
    with embed_tab:
        with st.form("stego_embed_form"):
            recipient = st.selectbox("Penerima pesan tersembunyi", db.list_users(), key="stego_recipient")
            image_file = st.file_uploader("Pilih gambar PNG/JPG", type=["png", "jpg", "jpeg"], key="stego_image")
            secret_text = st.text_area("Pesan rahasia", height=100, key="stego_message")
            embed = st.form_submit_button("Enkripsi dan sembunyikan pesan", type="primary", use_container_width=True)
        if embed:
            if image_file is None or not secret_text.strip():
                st.error("Pilih gambar dan isi pesan rahasia.")
            else:
                try:
                    sender = db.get_user(username)
                    receiver = db.get_user(recipient)
                    envelope = encrypt_super_text(secret_text, sender["public_key"], receiver["public_key"])
                    payload = _pack_stego_envelope(envelope, username, recipient)
                    stego_png = embed_payload(image_file.getvalue(), payload)
                    st.success("Pesan terenkripsi berhasil disisipkan ke gambar.")
                    st.image(stego_png, caption="Gambar hasil steganografi", use_container_width=True)
                    st.download_button("Unduh gambar PNG", data=stego_png, file_name="securehub_stego.png", mime="image/png", use_container_width=True)
                except Exception as exc:
                    st.error(f"Gagal menyisipkan pesan: {exc}")
    with extract_tab:
        stego_file = st.file_uploader("Unggah gambar yang berisi pesan", type=["png"], key="stego_extract_image")
        if st.button("Ekstrak dan dekripsi pesan", key="extract_stego_button", use_container_width=True, disabled=stego_file is None):
            try:
                payload = extract_payload(stego_file.getvalue())
                envelope = _unpack_stego_envelope(payload)
                if username.lower() == envelope["sender"].lower():
                    role = "sender"
                elif username.lower() == envelope["recipient"].lower():
                    role = "recipient"
                else:
                    raise ValueError("Akun ini bukan pengirim atau penerima pesan tersembunyi.")
                plain = decrypt_super_text(envelope, st.session_state.private_key, role)
                st.success(f"Pesan berhasil diekstrak. Pengirim: {envelope['sender']} · Penerima: {envelope['recipient']}")
                st.text_area("Isi pesan tersembunyi", value=plain, height=130, disabled=True)
            except Exception as exc:
                st.error(f"Ekstraksi/dekripsi gagal: {exc}")


def render_assets(username: str) -> None:
    st.subheader("Pengelolaan aset digital")
    st.caption("Setiap pendaftaran dan perpindahan aset menghasilkan blok baru dalam ledger lokal.")
    with st.form("create_asset_form"):
        name = st.text_input("Nama aset")
        description = st.text_area("Deskripsi aset", height=80)
        create = st.form_submit_button("Daftarkan aset", type="primary", use_container_width=True)
    if create:
        if not name.strip():
            st.error("Nama aset harus diisi.")
        else:
            asset_id = str(uuid.uuid4())
            timestamp = utc_now()
            db.insert_asset(asset_id, username, name.strip(), description.strip(), timestamp)
            blockchain.add_ledger_record({
                "action": "CREATE_ASSET", "asset_id": asset_id, "asset_name": name.strip(),
                "actor": username, "from_owner": None, "to_owner": username,
            }, timestamp)
            st.success(f"Aset berhasil didaftarkan. ID: {asset_id[:8]}")
    st.divider()
    owned = db.get_assets(username)
    st.markdown("**Aset milik akun ini**")
    if not owned:
        st.info("Belum ada aset yang dimiliki.")
    for asset in owned:
        with st.container(border=True):
            st.markdown(f"**{asset['name']}**  ")
            st.caption(f"ID: {asset['id']} · Dibuat: {asset['created_at']}")
            if asset["description"]:
                st.write(asset["description"])
    if owned and len(db.list_users()) > 1:
        st.divider()
        st.markdown("**Transfer aset**")
        asset_options = {f"{a['name']} ({a['id'][:8]})": a for a in owned}
        with st.form("transfer_asset_form"):
            selected_label = st.selectbox("Pilih aset", list(asset_options.keys()))
            targets = [u for u in db.list_users() if u.lower() != username.lower()]
            target = st.selectbox("Pemilik baru", targets)
            transfer = st.form_submit_button("Transfer dan catat ke blockchain", type="primary", use_container_width=True)
        if transfer:
            asset = asset_options[selected_label]
            timestamp = utc_now()
            db.transfer_asset(asset["id"], target)
            blockchain.add_ledger_record({
                "action": "TRANSFER_ASSET", "asset_id": asset["id"], "asset_name": asset["name"],
                "actor": username, "from_owner": username, "to_owner": target,
            }, timestamp)
            st.success(f"Aset berhasil dipindahkan kepada {target}.")


def render_blockchain() -> None:
    st.subheader("Blockchain sederhana")
    blocks = db.get_blocks()
    valid, message = blockchain.verify_chain()
    if valid:
        st.success(message)
    else:
        st.error(message)
    c1, c2 = st.columns(2)
    with c1:
        st.metric("Jumlah blok", len(blocks))
    with c2:
        st.metric("Proof-of-work", f"{blockchain.DIFFICULTY} nol di depan")
    if not blocks:
        st.info("Belum ada transaksi aset yang dicatat.")
    for block in reversed(blocks):
        payload = json.loads(block["payload_json"])
        with st.expander(f"Blok #{block['block_index']} · {payload.get('action', 'TRANSAKSI')}"):
            st.json(payload)
            st.caption(f"Waktu: {block['timestamp']}")
            st.code(f"Previous hash: {block['previous_hash']}\nHash: {block['block_hash']}\nNonce: {block['nonce']}")
    if st.button("Verifikasi ulang seluruh rantai", use_container_width=True):
        ok, detail = blockchain.verify_chain()
        if ok:
            st.success(detail)
        else:
            st.error(detail)


def render_user_management(username: str) -> None:
    user = db.get_user(username)
    if user["role"] != "admin":
        st.info("Hanya administrator yang dapat membuat akun pengguna.")
        return
    st.subheader("Manajemen pengguna")
    with st.form("create_user_form"):
        new_username = st.text_input("Username pengguna baru")
        new_password = st.text_input("Password sementara", type="password")
        create = st.form_submit_button("Buat akun dan daftarkan biometrik", type="primary", use_container_width=True)
    if create:
        new_username = new_username.strip()
        if len(new_username) < 3 or not new_username.replace("_", "").isalnum():
            st.error("Username minimal 3 karakter; gunakan huruf, angka, atau underscore.")
        elif len(new_password) < 10:
            st.error("Password minimal 10 karakter.")
        elif db.get_user(new_username):
            st.error("Username sudah digunakan.")
        else:
            try:
                keys = create_user_crypto(new_password, new_username)
                db.insert_user({"username": new_username, **keys, "role": "user", "created_at": utc_now()})
                begin_face_enrollment(new_username, new_password, False)
                st.rerun()
            except Exception as exc:
                st.error(f"Gagal membuat pengguna: {exc}")
    st.divider()
    st.markdown("**Akun terdaftar**")
    for name in db.list_users():
        record = db.get_user(name)
        status = "Biometrik siap" if record["face_enc"] else "Biometrik belum didaftarkan"
        st.write(f"- **{name}** — {record['role']} — {status}")

    incomplete = [name for name in db.list_users() if not db.get_user(name)["face_enc"]]
    if incomplete:
        with st.expander("Lanjutkan pendaftaran biometrik yang belum selesai"):
            st.caption("Gunakan username dan password akun yang belum memiliki data biometrik.")
            retry_username = st.selectbox("Akun", incomplete, key="retry_face_username")
            retry_password = st.text_input("Password akun", type="password", key="retry_face_password")
            if st.button("Lanjutkan pendaftaran wajah", key="retry_face_button", use_container_width=True):
                retry_user = db.get_user(retry_username)
                dongle_ok, dongle_message = find_connected_dongle(db.get_setting("dongle_hash"))
                if not dongle_ok:
                    st.error(dongle_message)
                elif not verify_password(retry_password, retry_user["password_salt"], retry_user["password_hash"]):
                    st.error("Password akun tidak sesuai.")
                else:
                    begin_face_enrollment(retry_username, retry_password, False)
                    st.rerun()


def render_dashboard() -> None:
    username = st.session_state.current_user
    user = db.get_user(username)
    dongle_ok, dongle_message = find_connected_dongle(db.get_setting("dongle_hash"))
    if not dongle_ok:
        clear_login()
        st.warning("Akses dikunci karena USB dongle tidak terdeteksi. Hubungkan dongle lalu login kembali.")
        st.rerun()
    st.sidebar.title("SecureHub")
    st.sidebar.write(f"Login sebagai **{username}**")
    st.sidebar.caption(dongle_message)
    if st.sidebar.button("Keluar", use_container_width=True):
        clear_login()
        st.rerun()
    if st.sidebar.button("Periksa USB sekarang", use_container_width=True):
        st.rerun()
    hero()
    st.title("Dashboard")
    c1, c2, c3 = st.columns(3)
    c1.metric("Pengguna", len(db.list_users()))
    c2.metric("Pesan masuk", len(db.get_messages(username, "inbox")))
    c3.metric("Aset dimiliki", len(db.get_assets(username)))
    st.caption("Pesan dan file dienkripsi sebelum disimpan. Kunci privat akun hanya dibuka setelah autentikasi.")

    tabs = st.tabs(["Pesan", "File", "Catatan", "Steganografi", "Aset", "Blockchain", "Pengguna"])
    with tabs[0]:
        render_messages(username)
    with tabs[1]:
        render_files(username)
    with tabs[2]:
        render_notes(username)
    with tabs[3]:
        render_steganography(username)
    with tabs[4]:
        render_assets(username)
    with tabs[5]:
        render_blockchain()
    with tabs[6]:
        render_user_management(username)


def main() -> None:
    db.init_db()
    init_session()

    if st.session_state.pending_enroll_username:
        dongle_ok, dongle_message = find_connected_dongle(db.get_setting("dongle_hash"))
        if not dongle_ok:
            st.error(dongle_message)
            st.stop()
        render_face_enrollment()
        return

    if db.user_count() == 0:
        render_first_setup()
        return

    if not st.session_state.logged_in:
        render_login()
        return

    render_dashboard()


if __name__ == "__main__":
    main()
