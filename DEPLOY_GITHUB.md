# Panduan Deploy Gratis HSE SYSTEM ke GitHub & Hosting Cloud

Aplikasi **HSE SYSTEM** menggunakan arsitektur Full-Stack (Frontend React + Backend Express + Database SQLite). Karena memiliki backend & upload file, deployment dilakukan dengan menyimpan source code di **GitHub** lalu menghubungkannya ke layanan hosting Node.js gratis (**Render.com** atau **Koyeb**).

---

## Tahap 1: Persiapan Akun & Repository GitHub

1. Buka [https://github.com](https://github.com) lalu Login atau buat akun baru (gratis).
2. Klik ikon **+** di kanan atas → pilih **New repository**.
3. Isi nama repository, misalnya: `hse-system`.
4. Pilih **Public** (atau Private), jangan centang README/gitignore jika kode sudah ada, lalu klik **Create repository**.

---

## Tahap 2: Upload Kode Aplikasi ke GitHub

Pastikan Git sudah terpasang di komputer Anda, lalu buka Terminal / Command Prompt di dalam folder root project aplikasi ini:

```bash
git init
git add .
git commit -m "Deploy perdana HSE SYSTEM"
git branch -M main
git remote add origin https://github.com/USERNAME_GITHUB_ANDA/hse-system.git
git push -u origin main
```

---

## Tahap 3: Deploy Gratis ke Render.com (HTTPS Otomatis)

HTTPS wajib aktif agar kamera smartphone dapat digunakan untuk fitur **Scan QR Code**. Render.com menyediakan HTTPS gratis secara otomatis.

1. Buka [https://render.com](https://render.com) → klik **Get Started for Free** → pilih **Continue with GitHub**.
2. Dari Dashboard Render, klik **New +** → pilih **Web Service**.
3. Pilih repository `hse-system` yang baru saja Anda upload.
4. Isi konfigurasi berikut:
   - **Name**: `hse-system`
   - **Region**: `Singapore` (terdekat dengan Indonesia)
   - **Branch**: `main`
   - **Runtime**: `Node`
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm start`
5. Pada bagian **Instance Type**, pilih **Free ($0/month)**.
6. Tambahkan **Environment Variables** (klik *Add Environment Variable*):
   - `NODE_ENV` = `production`
   - `SESSION_SECRET` = `ganti_dengan_teks_acak_yang_kuat_2026`
7. Klik **Deploy Web Service**.

Tunggu 2–4 menit hingga status menjadi **Live**. Anda akan mendapatkan link aplikasi resmi seperti `https://hse-system.onrender.com` yang langsung bisa dibuka dari HP, tablet, dan PC.

---

## Tahap 4: Akun Login Bawaan

Aplikasi langsung dapat diakses tanpa login untuk melihat dashboard dan melakukan pemindaian QR. Untuk mengakses fitur administrasi:

| Peran | Username | Password |
| :--- | :--- | :--- |
| **ADMIN** | `admin` | `admin123` |
| **INSPECTOR** | `inspector` | `inspector123` |
| **VIEWER** | `viewer` | `viewer123` |

*Segera ubah password akun bawaan melalui menu **Sistem → Manajemen User** setelah aplikasi online.*

---

## Catatan Penyimpanan Data (Gratis vs Produksi Pabrik)

- Pada **Free Tier Render**, penyimpanan file lokal akan di-reset jika layanan tidak aktif/restart ulang.
- Gunakan fitur **Sistem → Backup & Restore → Download Backup JSON** secara berkala, atau tambahkan Render Persistent Disk / migrasi `src/server/db.ts` ke PostgreSQL gratis (Neon / Supabase) untuk penyimpanan permanen jangka panjang.
