# SecureHub — Aplikasi Pesan Aman

SecureHub adalah aplikasi desktop-local berbasis Streamlit untuk demonstrasi tugas akhir Kriptografi. Aplikasi menggabungkan autentikasi, enkripsi pesan dan file, penyimpanan catatan rahasia, steganografi gambar, serta blockchain sederhana untuk pencatatan aset.

## Fitur yang tersedia

1. **Login berlapis**: password dengan PBKDF2-HMAC-SHA256, USB dongle berupa token file pada removable drive, dan pencocokan wajah lokal melalui webcam (OpenCV LBPH).
2. **Super-enkripsi pesan teks**: Vigenère Cipher dilanjutkan AES-256-GCM. Kunci AES dan kunci Vigenère dibungkus dengan RSA-OAEP milik pengirim dan penerima.
3. **Enkripsi file**: file memakai AES-256-GCM (berbeda dari alur super-enkripsi teks). Kunci file dibungkus RSA-OAEP.
4. **Catatan penting terenkripsi**: isi catatan dienkripsi sebelum disimpan ke SQLite; kunci AES dibungkus RSA.
5. **Steganografi gambar**: pesan dienkripsi terlebih dahulu, lalu disisipkan ke bit paling rendah (LSB) kanal RGB. Gambar keluaran disimpan sebagai PNG.
6. **Blockchain sederhana**: pencatatan pembuatan dan transfer aset memakai rantai hash SHA-256, previous hash, dan proof-of-work sederhana.
7. **Multi-pengguna**: administrator dapat membuat akun lain. Setiap pengguna harus mendaftarkan biometriknya sendiri.

## Kebutuhan

- Python 3.10 atau lebih baru.
- Webcam yang dapat digunakan browser.
- USB flash drive yang dikenali sistem operasi sebagai removable drive.
- Windows 10/11, Linux, atau macOS (pemeriksaan removable-drive paling langsung diuji untuk Windows).

## Instalasi dan menjalankan di Windows

1. Ekstrak ZIP ke folder biasa, misalnya `C:\\SecureHub`.
2. Hubungkan USB flash drive yang akan dijadikan dongle.
3. Pastikan Python 3.10+ sudah terpasang dan opsi **Add Python to PATH** diaktifkan.
4. Klik dua kali `install_and_run_windows.bat`. Instalasi dependensi dilakukan otomatis pada pemakaian pertama.
5. Browser akan terbuka ke alamat lokal Streamlit (umumnya `http://localhost:8501`). Berikan izin penggunaan kamera.

Untuk menjalankan berikutnya, gunakan `run_windows.bat`.

## Pengaturan pertama

1. Pada halaman awal, buat username dan password administrator (minimal 10 karakter).
2. Isi lokasi USB, misalnya `E:\\` (gunakan root drive, bukan nama file).
3. Klik **Buat akun dan daftarkan USB**. SecureHub membuat file `SECUREHUB_DONGLE.key` pada USB tersebut.
4. Kamera akan meminta minimal tiga sampel wajah. Ambil sampel dengan sedikit perubahan sudut dan pencahayaan.
5. Setelah biometrik disimpan, dashboard terbuka.
6. Untuk membuat akun lain, buka tab **Pengguna**. Akun baru juga harus melakukan pendaftaran wajah.

Setiap login membutuhkan password, USB yang sama, dan wajah yang cocok. Jika USB dilepas, aplikasi mengunci akses pada pemuatan/aksi Streamlit berikutnya; muat ulang halaman setelah melepas atau memasang USB.

## Menjalankan di Linux/macOS

Jalankan dari terminal:

```bash
chmod +x run_linux.sh
./run_linux.sh
```

Di Linux, pemeriksaan USB membaca informasi removable dari `/sys/class/block`. Pastikan perangkat fingerprint/camera atau webcam tersedia. Di macOS, deteksi drive menggunakan informasi `diskutil`.

## Struktur proyek

```text
securehub_app/
├── app.py
├── requirements.txt
├── README.md
├── install_and_run_windows.bat
├── run_windows.bat
├── run_linux.sh
├── securehub/
│   ├── db.py
│   ├── crypto_utils.py
│   ├── biometric.py
│   ├── dongle.py
│   ├── steganography.py
│   └── blockchain.py
├── tests/
│   └── test_core.py
└── data/                 # dibuat otomatis saat aplikasi berjalan
    └── securehub.db
```

## Lokasi database

Database SQLite dibuat otomatis di `data/securehub.db`. Database berisi akun, kunci publik, kunci privat terenkripsi, pesan ciphertext, file ciphertext, catatan ciphertext, data aset, dan ledger blockchain. Jangan menghapus folder `data` selama masih ingin menggunakan akun dan data yang tersimpan.

## Catatan keamanan dan batasan

- Ini adalah **prototipe akademik lokal**, bukan aplikasi produksi. Jalankan hanya pada komputer tepercaya dan jangan membuka server Streamlit ke jaringan publik.
- Biometrik memakai OpenCV LBPH dengan deteksi wajah Haar Cascade. Metode ini tidak memiliki liveness detection; foto wajah dapat menjadi risiko spoofing. Template wajah disimpan dalam bentuk terenkripsi, tetapi kualitas autentikasinya tidak setara Face ID/Windows Hello atau perangkat biometrik bersertifikat.
- USB dongle adalah token acak dalam file `SECUREHUB_DONGLE.key` pada removable drive. File token dapat disalin oleh pihak yang memiliki akses fisik ke USB; ini bukan dongle kriptografis anti-kloning.
- Vigenère digunakan untuk memenuhi demonstrasi kriptografi klasik, bukan sebagai perlindungan modern yang berdiri sendiri. Keamanan utama pesan berasal dari AES-GCM dan RSA-OAEP.
- Blockchain yang dibuat adalah ledger lokal untuk demonstrasi integritas. Ia bukan jaringan blockchain terdistribusi dan tidak menyediakan konsensus antarserver.
- Kunci privat RSA dienkripsi menggunakan kunci turunan password. Jika password hilang, data terenkripsi tidak dapat dipulihkan melalui fitur reset password.
- Hindari mengirim file yang sangat besar; batas unggah aplikasi adalah 10 MB per file.

## Mode pengembangan USB virtual (opsional)

Hanya untuk pengujian saat tidak memiliki USB fisik. Mode ini **menonaktifkan pemeriksaan removable drive**, sehingga jangan digunakan saat demonstrasi persyaratan keamanan USB. Dari Command Prompt Windows:

```bat
set SECUREHUB_DEV_ALLOW_VIRTUAL_USB=1
.venv\Scripts\python.exe -m streamlit run app.py
```

Di Linux/macOS:

```bash
SECUREHUB_DEV_ALLOW_VIRTUAL_USB=1 .venv/bin/python -m streamlit run app.py
```

Variabel ini tidak aktif secara default.
