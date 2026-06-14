from flask import Flask, render_template, request, redirect, url_for
import hashlib
import random

app = Flask(__name__)

# ==============================================================================
# LOG PROSES TAHAP 1 & 2: DEFINISI MASALAH, LOGIKA PROPOSISI, & TEORI HIMPUNAN
# ==============================================================================

"""
1. SPESIFIKASI ALGEBRA HIMPUNAN:
   Misalkan:
   - U adalah Himpunan Semesta (Universe of Discourse) dari seluruh entitas pengguna.
     U = { x | x adalah kredensial pengguna yang terdaftar pada sistem }
   
   - A adalah Himpunan Bagian (Subset) dari U yang merepresentasikan pengguna dengan status aktif.
     A = { x ∈ U | status(x) = 1 }
     Maka berdasarkan aksioma himpunan, berlaku hukum: A ⊆ U
   
   - S adalah Himpunan Semesta dari seluruh Hak Akses / Kapabilitas Fungsi (Otorisasi) di dalam sistem.
     S = { Read, Write, Delete }
"""

database_user = {
    "neysa-admin": {
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "role": "Admin",
        "status": 1  # Korelasi: rian_admin ∈ A (Elemen Himpunan Bagian Aktif)
    },
    "intan-operator": {
        "password_hash": hashlib.sha256("op123".encode()).hexdigest(),
        "role": "Operator",
        "status": 1  # Korelasi: budi_operator ∈ A (Elemen Himpunan Bagian Aktif)
    },
    "nazwa-user": {
        "password_hash": hashlib.sha256("user123".encode()).hexdigest(),
        "role": "User",
        "status": 0  # Korelasi: joko_user ∉ A ∧ joko_user ∈ (U - A)
    }
}

"""
2. TEORI RELASI BINER (RELASI HIMPUNAN MULTI-PROPERTI):
   Misalkan:
   - R adalah Relasi Biner yang memetakan elemen dari Himpunan Tingkatan Otoritas (Role) 
     ke Himpunan Kuasa (Power Set) dari Fitur Aplikasi P(S).
     R: Role → P(S)
   
   Definisi Subset Hasil Relasi Konten:
   - Akses_Admin    = { x ∈ S | (Admin, x) ∈ R }    = S          (Sifat: Subset Kompleksitas Penuh)
   - Akses_Operator = { x ∈ S | (Operator, x) ∈ R } = {Read, Write} (Sifat: Akses_Operator ⊂ S)
   - Akses_User     = { x ∈ S | (User, x) ∈ R }     = {Read}     (Sifat: Akses_User ⊂ S)
"""
relasi_role_akses = {
    "Admin": {"Read", "Write", "Delete"},
    "Operator": {"Read", "Write"},
    "User": {"Read"}
}

# Fungsi memori stateful untuk penyimpanan token OTP sementara
otp_memory = {}

# ==============================================================================
# ALUR PROSES WEB HANDLER (FLASK CORE ENGINE)
# ==============================================================================

@app.route('/')
def index():
    return render_template('index.html', step='login')

@app.route('/auth', methods=['POST'])
def auth():
    username = request.form.get('username')
    password = request.form.get('password')
    role_input = request.form.get('role_input')
    
    # --------------------------------------------------------------------------
    # EVALUASI PROPOSISI ATOMIK 'p' (Validasi Kredensial Pengguna)
    # Definisi Formal: 
    # p ≡ (username ∈ U) ∧ (hash(password) == database[username].hash) ∧ (role_input == database[username].role)
    # --------------------------------------------------------------------------
    
    # Gerbang Evaluasi 1: username ∈ U
    if username not in database_user:
        return render_template('index.html', error_msg="Username salah atau tidak terdaftar.")
    
    # Gerbang Evaluasi 2 & 3: KRIPTOGRAFI HASHING SHA-256 & KESESUAIAN DATA
    hashed_input = hashlib.sha256(password.encode()).hexdigest()
    if hashed_input != database_user[username]["password_hash"]:
        return render_template('index.html', error_msg="Password salah atau tidak terdaftar.")
        
    if role_input != database_user[username]["role"]:
        return render_template('index.html', error_msg="Tingkat otoritas role tidak sesuai.")
    
    # Jika seluruh syarat konjungsi internal terpenuhi, maka nilai kebenaran Proposisi p = True (T)
    p = True

    # --------------------------------------------------------------------------
    # EVALUASI PROPOSISI ATOMIK 'q' (Validasi Keanggotaan Akun Aktif)
    # Definisi Formal:
    # q ≡ (username ∈ A)
    # --------------------------------------------------------------------------
    if database_user[username]["status"] != 1:
        # Jika syarat status tidak terpenuhi, maka (username ∈ A) bernilai False (F), berakibat q = False (F)
        return render_template('index.html', error_msg="Akses ditolak. Status akun Anda tidak aktif.")
    
    # Jika elemen merupakan anggota dari Himpunan A, maka nilai kebenaran Proposisi q = True (T)
    q = True
    
    # --------------------------------------------------------------------------
    # LOG PROSES TAHAP 3: KOMBINATORIKA (Kaidah Perkalian & Pencacahan Ruang OTP)
    # Teorema Kombinatorika:
    # Jika sebuah string OTP terdiri dari n = 4 digit ruang kosong, dan setiap ruang kosong 
    # memiliki peluang k = 10 variasi angka (0,1,2,3,4,5,6,7,8,9), maka berdasarkan Kaidah Perkalian 
    # (Rule of Product), total variasi ruang sampel kombinasi yang dapat terbentuk adalah:
    # |Kombinasi_OTP| = k × k × k × k = k^n = 10^4 = 10.000 Variasi Probabilitas Kemungkinan.
    # --------------------------------------------------------------------------
    otp_code = "".join([str(random.randint(0, 9)) for _ in range(4)])
    otp_memory[username] = otp_code
    
    # Jika kondisi konjungsi logis antara kedua proposisi (p ∧ q) bernilai True (T), 
    # maka sistem meneruskan alur ke tahap tantangan (challenge) OTP.
    return render_template('index.html', step='otp', username=username, otp_code=otp_code)

@app.route('/verify', methods=['POST'])
def verify():
    username = request.form.get('username')
    otp_input = request.form.get('otp_input')
    
    # Berdasarkan struktur prasyarat (precondition), Proposisi p dan q bernilai True (T)
    p = True
    q = True
    
    # --------------------------------------------------------------------------
    # EVALUASI PROPOSISI ATOMIK 'r' (Kesesuaian Masukan Token Keamanan)
    # Definisi Formal:
    # r ≡ (otp_input == otp_memory[username])
    # --------------------------------------------------------------------------
    if username in otp_memory and otp_input == otp_memory[username]:
        r = True
    else:
        r = False
        # Mitigasi Keamanan: Jika r = False (F), lakukan permutasi ulang nilai kombinasi OTP 
        # untuk menjaga derajat entropi sistem.
        otp_code = "".join([str(random.randint(0, 9)) for _ in range(4)])
        otp_memory[username] = otp_code
        return render_template('index.html', step='otp', username=username, otp_code=otp_code, error_msg="Kode keamanan OTP salah.")
    
    # --------------------------------------------------------------------------
    # LOG PROSES TAHAP 5: FUNGSI VALIDASI LOGIKA MAJEMUK (CONJUNCTION EVALUATION)
    # Rumus Utama Logika Proposisi Majemuk: 
    # L(p, q, r) = p ∧ q ∧ r
    # 
    # Aturan Inferensi: Akses ke dalam sistem hanya diberikan (Otorisasi Sukses) 
    # jika dan hanya jika fungsi L(p, q, r) menghasilkan nilai TAUTOLOGI mutlak, yaitu True (T).
    # --------------------------------------------------------------------------
    L = p and q and r
    
    if L == True:
        role = database_user[username]["role"]
        
        # OPERASI HIMPUNAN: Mengambil subset fungsional berdasarkan pemetaan Relasi R
        # Hak_Akses = { x ∈ S | (role, x) ∈ R }
        hak_akses_himpunan = list(relasi_role_akses[role])
        
        # Flush token memori demi menjaga aspek non-repudiation
        if username in otp_memory:
            del otp_memory[username]
            
        # Passing variabel parameter subset menuju komponen View (Front-End)
        return render_template('index.html', step='dashboard', username=username, role=role, hak_akses=hak_akses_himpunan)
    else:
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)