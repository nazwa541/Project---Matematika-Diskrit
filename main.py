from flask import Flask, render_template, request
import math

app = Flask(__name__)

# =====================================================================
# DATA & RUMUS MATEMATIKA DISKRIT
# =====================================================================
DATABASE_USER = {
    "budi_mhs":   {"password_hash": "eoxguld",   "status": "Aktif",       "role": "Mahasiswa"}, # asli: budi123
    "andi_dosen": {"password_hash": "grvhq123",  "status": "Aktif",       "role": "Dosen"},     # asli: dosen123
    "admin_pcr":  {"password_hash": "dgplq",     "status": "Tidak Aktif", "role": "Admin"}      # asli: admin
}

RELASI_HAK_AKSES = {
    "Admin":     {"Create", "Read", "Update", "Delete"},
    "Dosen":     {"Create", "Read", "Update"},
    "Mahasiswa": {"Read"}
}

def enkripsi_modulo_128(password: str, key: int = 3) -> str:
    # Rumus Kriptografi Modulo: E(x) = (x + k) mod 128
    cipher_text = ""
    for karakter in password:
        cipher_text += chr((ord(karakter) + key) % 128)
    return cipher_text

def hitung_variasi_otp(panjang_otp: int = 6) -> int:
    # Kombinatorika aturan perkalian: 10^6
    return int(math.pow(10, panjang_otp))

# =====================================================================
# ROUTING SERVER WEB FLASK
# =====================================================================
@app.route("/", methods=["GET", "POST"])
def login_page():
    hasil_analisis = None
    
    if request.method == "POST":
        username_input = request.form.get("username")
        password_input = request.form.get("password")
        role_input = request.form.get("role")
        
        # 1. Enkripsi Input Password
        hash_input = enkripsi_modulo_128(password_input)
        
        # 2. Evaluasi Kebenaran Proposisi (Logika Matematika)
        p = (username_input in DATABASE_USER) and (DATABASE_USER[username_input]["password_hash"] == hash_input)
        q = username_input in DATABASE_USER and DATABASE_USER[username_input]["status"] == "Aktif"
        r = username_input in DATABASE_USER and DATABASE_USER[username_input]["role"] == role_input
        
        # Aturan Logika Konjungsi Majemuk
        akses_diterima = p and q and r
        
        # Tentukan pesan jika gagal logika
        pesan_gagal = ""
        hak_akses_user = []
        if akses_diterima:
            # Mengambil Hak Akses berdasarkan Relasi Himpunan Peran
            hak_akses_user = list(RELASI_HAK_AKSES[role_input])
        else:
            if not p:
                pesan_gagal = "Proposisi p bernilai SALAH. Username atau Password salah (Hasil enkripsi hash tidak cocok)."
            elif not q:
                pesan_gagal = "Proposisi q bernilai SALAH. Akun ini berstatus 'Tidak Aktif'."
            elif not r:
                pesan_gagal = "Proposisi r bernilai SALAH. Kredensial benar, tetapi Peran/Role yang Anda pilih tidak sesuai."

        # Bungkus data untuk dikirim ke halaman HTML web
        hasil_analisis = {
            "username": username_input,
            "hash_input": hash_input,
            "p": p,
            "q": q,
            "r": r,
            "akses_diterima": akses_diterima,
            "pesan_gagal": pesan_gagal,
            "hak_akses": hak_akses_user,
            "otp_kombinasi": hitung_variasi_otp(6)
        }
        
    return render_template("login.html", hasil=hasil_analisis)

if __name__ == "__main__":
    # Menjalankan server Flask secara lokal dengan mode debug aktif
    app.run(debug=True)