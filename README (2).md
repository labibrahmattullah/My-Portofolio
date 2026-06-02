# 🌐 Personal Portfolio Website

Selamat datang di repositori website portofolio personal saya. Website ini dirancang sebagai representasi digital dari keahlian, proyek, dan minat saya di bidang teknologi, khususnya **Informatics Engineering** dan **Cybersecurity**.

---

## 🚀 Fitur Utama
- **Hero Section**: Tampilan modern dengan tajuk utama yang bersih dan ajakan bertindak (CTA) yang responsif.
- **Project Showcase**: Daftar proyek yang pernah dikembangkan beserta deskripsi dan teknologi yang digunakan.
- **Social Connect**: Navigasi cepat menuju Email, LinkedIn, GitHub, dan pengunduhan CV (Curriculum Vitae).
- **Responsive Design**: Tampilan yang optimal di berbagai perangkat (Desktop, Tablet, dan Mobile).

---

## 🛠️ Teknologi yang Digunakan
- **HTML5 & CSS3**: Struktur semantik dan styling kustom (termasuk penataan tipografi serif yang elegan).
- **VS Code**: Editor teks utama yang digunakan selama proses pengembangan.
- **Git & GitHub**: Digunakan untuk version control dan hosting repositori.

---

## 📌 Panduan Troubleshooting Kustomisasi Layout

### 1. Memperbaiki Teks Heading Menjadi Satu Baris (1 Row)
Jika Anda mengalami masalah di mana teks utama seperti **"Siap Berkolaborasi?"** otomatis terpotong menjadi dua baris (seperti pada gambar `Screenshot 2026-06-02 213902.jpg`), berikut adalah cara memperbaikinya di VS Code:

#### A. Cek Struktur HTML
Pastikan teks ditulis dalam satu elemen utuh dan tidak mengandung tag `<br>` (line break) di tengah kata:
```html
<!-- BENAR: Teks akan mengalir dalam satu baris -->
<h1 class="hero-title">Siap Berkolaborasi?</h1>

<!-- SALAH (Penyebab teks turun): -->
<!-- <h1>Siap <br> Berkolaborasi?</h1> -->
```

#### B. Tambahkan Aturan CSS (Mencegah Auto-Wrap)
Jika teks tetap turun akibat keterbatasan lebar kontainer induk, paksa elemen agar tetap berada dalam satu baris menggunakan properti `white-space`:
```css
.hero-title {
    font-family: 'Playfair Display', serif; /* Sesuaikan dengan font website Anda */
    text-align: center;
    
    /* Kode utama untuk memaksa teks menjadi 1 row */
    white-space: nowrap; 
}
```

#### C. Solusi Menggunakan Tailwind CSS
Jika proyek ini dikembangkan menggunakan utilitas Tailwind CSS, cukup tambahkan class `whitespace-nowrap`:
```html
<h1 class="text-center font-serif text-5xl font-bold whitespace-nowrap">
  Siap Berkolaborasi?
</h1>
```

---

## ⚙️ Cara Menjalankan Proyek Secara Lokal

1. **Clone Repositori Ini**
   ```bash
   git clone https://github.com/username/portfolio.git
   ```
2. **Masuk ke Direktori Proyek**
   ```bash
   cd portfolio
   ```
3. **Buka Menggunakan VS Code**
   ```bash
   code .
   ```
4. **Jalankan Website**
   - Jika menggunakan ekstensi **Live Server** di VS Code, klik kanan pada file `index.html` lalu pilih **"Open with Live Server"**.
   - Atau, cukup klik ganda file `index.html` untuk membukanya langsung di browser favorit Anda.

---

## 📄 Lisensi
Proyek ini dilisensikan di bawah [MIT License](LICENSE). Anda bebas menggunakannya untuk referensi atau memodifikasinya menjadi portofolio pribadi Anda.
