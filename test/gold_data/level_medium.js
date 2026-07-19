const express = require('express');
const crypto = require('crypto');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'appdb'
});

const JWT_SECRET = "my_jwt_secret_key";

// 인증 미들웨어 (중급 문제에서 공통 사용)
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ============================================
// [GOLD-M01] SQL Injection (중) - 불완전한 sanitize 우회
// CWE-89 | ISMS-P 2.8.1
// ============================================
const sanitize = (input) => {
  // 따옴표만 제거 — UNION SELECT, 숫자 기반 인젝션은 차단 못함
  return input.replace(/'/g, '').replace(/"/g, '');
};

app.get('/api/products', (req, res) => {
  const category = sanitize(req.query.category);
  const query = `SELECT * FROM products WHERE category = ${category} ORDER BY price`;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: "Query failed" });
    res.json(results);
  });
});

// ============================================
// [GOLD-M02] XSS (중) - Stored XSS, DB 저장 후 관리자 페이지 출력
// CWE-79 | ISMS-P 2.8.1
// ============================================
app.post('/api/comments', authMiddleware, (req, res) => {
  const { content } = req.body;
  // 입력 시 검증 없이 DB에 저장
  db.query("INSERT INTO comments (user_id, content) VALUES (?, ?)", [req.user.id, content], (err) => {
    if (err) return res.status(500).json({ error: "Save failed" });
    res.json({ success: true });
  });
});

app.get('/api/admin/comments', authMiddleware, (req, res) => {
  db.query("SELECT * FROM comments", (err, results) => {
    if (err) return res.status(500).json({ error: "Query failed" });
    // 관리자 페이지에서 이스케이프 없이 HTML로 렌더링
    let html = "<h1>댓글 관리</h1><ul>";
    for (const row of results) {
      html += `<li>${row.content} - by user ${row.user_id}</li>`;
    }
    html += "</ul>";
    res.send(html);
  });
});

// ============================================
// [GOLD-M03] 취약한 암호화 (중) - SHA-256이지만 Salt 없음
// CWE-916 | ISMS-P 2.7.1
// ============================================
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  // SHA-256은 안전하지만 Salt가 없어 레인보우 테이블에 취약
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  db.query("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, hash], (err) => {
    if (err) return res.status(500).json({ error: "Registration failed" });
    res.json({ success: true });
  });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  db.query("SELECT * FROM users WHERE username = ? AND password_hash = ?", [username, hash], (err, results) => {
    if (err || results.length === 0) return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: results[0].id, username }, JWT_SECRET);
    res.json({ token });
  });
});

// ============================================
// [GOLD-M04] 접근 통제 누락 (중) - 인증은 있으나 리소스 소유권 미검증 (IDOR)
// CWE-639 | ISMS-P 2.6.1
// ============================================
app.get('/api/orders/:orderId', authMiddleware, (req, res) => {
  const orderId = req.params.orderId;
  // 인증된 사용자인지는 확인하지만, 해당 주문이 이 사용자의 것인지 검증하지 않음
  db.query("SELECT * FROM orders WHERE id = ?", [orderId], (err, results) => {
    if (err) return res.status(500).json({ error: "Query failed" });
    if (results.length === 0) return res.status(404).json({ error: "Order not found" });
    // req.user.id와 results[0].user_id 비교 없이 바로 반환
    res.json(results[0]);
  });
});

// ============================================
// [GOLD-M05] 민감 정보 노출 (중) - 로그에 비밀번호 평문 기록
// CWE-532 | ISMS-P 2.9.1
// ============================================
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  // 디버깅용 로그가 프로덕션에 남아 있음 — 비밀번호 평문 노출
  console.log(`[AUTH] Login attempt: username=${username}, password=${password}, ip=${req.ip}`);
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  db.query("SELECT * FROM users WHERE username = ? AND password_hash = ?", [username, hash], (err, results) => {
    if (err || results.length === 0) {
      console.log(`[AUTH] Login failed: username=${username}, password=${password}`);
      return res.status(401).json({ error: "Invalid credentials" });
    }
    console.log(`[AUTH] Login success: username=${username}`);
    res.json({ success: true, token: "jwt_token_here" });
  });
});

app.listen(3001, () => console.log('Level Medium app running on port 3001'));
