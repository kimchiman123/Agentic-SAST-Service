const express = require('express');
const crypto = require('crypto');
const mysql = require('mysql2');
const app = express();

app.use(express.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'appdb'
});

// ============================================
// [GOLD-L01] SQL Injection (하) - 직접 문자열 연결
// CWE-89 | ISMS-P 2.8.1
// ============================================
app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(results);
  });
});

// ============================================
// [GOLD-L02] XSS (하) - Reflected XSS, 이스케이프 없이 직접 출력
// CWE-79 | ISMS-P 2.8.1
// ============================================
app.get('/api/search', (req, res) => {
  const keyword = req.query.keyword;
  res.send("<h1>검색 결과: " + keyword + "</h1><p>결과가 없습니다.</p>");
});

// ============================================
// [GOLD-L03] 취약한 암호화 (하) - MD5 해싱
// CWE-328 | ISMS-P 2.7.1
// ============================================
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
  db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
    if (err) return res.status(500).json({ error: "Registration failed" });
    res.json({ success: true, msg: "User registered" });
  });
});

// ============================================
// [GOLD-L04] 접근 통제 누락 (하) - 인증 미들웨어 부재
// CWE-862 | ISMS-P 2.6.1
// ============================================
// 관리자 전용 API인데 인증 미들웨어가 없음
app.delete('/api/admin/users/:id', (req, res) => {
  const targetId = req.params.id;
  db.query("DELETE FROM users WHERE id = ?", [targetId], (err) => {
    if (err) return res.status(500).json({ error: "Delete failed" });
    res.json({ success: true, msg: `User ${targetId} deleted` });
  });
});

// ============================================
// [GOLD-L05] 민감 정보 노출 (하) - 에러 스택 트레이스 노출
// CWE-209 | ISMS-P 2.9.1
// ============================================
app.get('/api/profile', (req, res) => {
  try {
    const data = JSON.parse(req.query.data);
    res.json(data);
  } catch (err) {
    res.status(500).json({
      error: err.message,
      stack: err.stack,
      env: process.env.NODE_ENV
    });
  }
});

app.listen(3000, () => console.log('Level Easy app running on port 3000'));
