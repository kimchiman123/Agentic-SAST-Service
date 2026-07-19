const express = require('express');
const crypto = require('crypto');
const { Sequelize, DataTypes } = require('sequelize');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

const sequelize = new Sequelize('appdb', 'root', 'root', {
  host: 'localhost',
  dialect: 'mysql'
});

const User = sequelize.define('User', {
  username: DataTypes.STRING,
  password: DataTypes.STRING,
  ssn: DataTypes.STRING,
  email: DataTypes.STRING,
  role: DataTypes.STRING
});

const JWT_SECRET = "my_jwt_secret_key";
let sessions = {};
let resetTokens = {};

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
// [GOLD-H01] SQL Injection (상) - ORM 내 Raw Query 인젝션
// CWE-89 | ISMS-P 2.8.1
// ============================================
const buildSearchQuery = (filters) => {
  let conditions = [];
  if (filters.username) conditions.push(`username LIKE '%${filters.username}%'`);
  if (filters.role) conditions.push(`role = '${filters.role}'`);
  if (filters.email) conditions.push(`email LIKE '%${filters.email}%'`);
  return conditions.length > 0 ? conditions.join(' AND ') : '1=1';
};

app.get('/api/admin/users/search', authMiddleware, async (req, res) => {
  try {
    // Sequelize ORM을 사용하지만 sequelize.query()에 raw SQL을 문자열 연결로 전달
    const whereClause = buildSearchQuery(req.query);
    const [results] = await sequelize.query(
      `SELECT id, username, email, role FROM Users WHERE ${whereClause} ORDER BY id`
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: "Search failed" });
  }
});

// ============================================
// [GOLD-H02] XSS (상) - DOM-based XSS (API 응답 → innerHTML)
// CWE-79 | ISMS-P 2.8.1
// ============================================
// 서버: 사용자 프로필 데이터를 sanitize 없이 저장·반환
app.put('/api/profile', authMiddleware, async (req, res) => {
  const { nickname, bio } = req.body;
  // 입력 검증/이스케이프 없이 그대로 저장
  await User.update({ nickname, bio }, { where: { id: req.user.id } });
  res.json({ success: true });
});

app.get('/api/profile/:userId', async (req, res) => {
  const user = await User.findByPk(req.params.userId, {
    attributes: ['id', 'username', 'nickname', 'bio']
  });
  if (!user) return res.status(404).json({ error: "Not found" });
  // 클라이언트가 이 JSON을 innerHTML로 렌더링하면 XSS 발생
  // 프론트엔드 예시: document.getElementById('bio').innerHTML = data.bio;
  res.json(user);
});

// ============================================
// [GOLD-H03] 취약한 암호화 (상) - AES-ECB + 하드코딩 키 복합 결함
// CWE-327 | ISMS-P 2.7.1
// ============================================
const ENCRYPTION_KEY = "hardcoded_key!!!"; // 16바이트 고정 키

const encryptData = (plaintext) => {
  // ECB 모드: 동일 평문 → 동일 암호문 (패턴 분석 가능)
  const cipher = crypto.createCipheriv('aes-128-ecb', ENCRYPTION_KEY, null);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
};

const decryptData = (ciphertext) => {
  const decipher = crypto.createDecipheriv('aes-128-ecb', ENCRYPTION_KEY, null);
  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

app.post('/api/payment/card', authMiddleware, (req, res) => {
  const { cardNumber, cvv, expiry } = req.body;
  const encryptedCard = encryptData(cardNumber);
  const encryptedCvv = encryptData(cvv);
  // DB에 암호화된 카드 정보 저장
  res.json({ success: true, msg: "Card saved", ref: encryptedCard.substring(0, 8) });
});

// ============================================
// [GOLD-H04] 접근 통제 누락 (상) - 다단계 상태 기반 권한 우회
// CWE-639 | ISMS-P 2.6.1
// ============================================
// Step 1: 비밀번호 초기화 토큰 발급
app.post('/api/auth/reset-request', (req, res) => {
  const { username } = req.body;
  const token = crypto.randomBytes(16).toString('hex');
  resetTokens[token] = username;
  res.json({ msg: "Reset token issued", token });
});

// Step 2: 토큰 검증 → 세션에 권한 부여
app.post('/api/auth/reset-verify', (req, res) => {
  const { token, sessionId } = req.body;
  if (resetTokens[token]) {
    sessions[sessionId] = {
      canResetPassword: true,
      owner: resetTokens[token]  // 토큰 소유자 기록
    };
    delete resetTokens[token];
    res.json({ msg: "Verified. You can now change password." });
  } else {
    res.status(400).json({ error: "Invalid token" });
  }
});

// Step 3: 비밀번호 변경 — 세션 소유자와 대상 불일치 미검증
app.post('/api/auth/reset-password', async (req, res) => {
  const { sessionId, targetUser, newPassword } = req.body;
  const session = sessions[sessionId];

  // 세션의 canResetPassword만 확인하고, session.owner === targetUser 검증 누락
  if (session && session.canResetPassword) {
    const hash = crypto.createHash('sha256').update(newPassword).digest('hex');
    await User.update({ password: hash }, { where: { username: targetUser } });
    session.canResetPassword = false;
    res.json({ msg: "Password changed successfully" });
  } else {
    res.status(403).json({ error: "Not authorized" });
  }
});

// ============================================
// [GOLD-H05] 민감 정보 노출 (상) - SELECT * + 권한별 필터링 부재
// CWE-200 | ISMS-P 2.9.1, 3.1.1
// ============================================
app.get('/api/users', authMiddleware, async (req, res) => {
  // SELECT * 로 전체 컬럼(주민번호, 비밀번호 해시 포함) 조회
  const users = await User.findAll();
  // 일반 사용자에게도 민감 필드를 포함한 전체 데이터 반환
  // req.user.role에 따른 필드 필터링 없음
  res.json(users);
});

app.listen(3002, () => console.log('Level Hard app running on port 3002'));
