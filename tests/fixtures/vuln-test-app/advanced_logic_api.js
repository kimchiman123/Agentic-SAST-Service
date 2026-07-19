const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

let usersDB = {
    "admin": { id: 1, balance: 10000, password: "hashed_password_1" },
    "user1": { id: 2, balance: 500, password: "hashed_password_2" }
};

let resetTokens = {}; // token -> username
let sessions = {}; // session_id -> { username, canResetPassword }

// ============================================
// [함정 1] 변수명 낚시 (False Positive 유도)
// ============================================
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    
    // No-CoT는 변수명(md5_hash)만 보고 취약한 해시 알고리즘 사용으로 오탐(FP)을 낼 확률이 높음.
    // 하지만 실제로는 pbkdf2Sync(강력한 해시)를 사용 중임.
    const salt = "random_salt_value";
    const insecure_md5_hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    
    if (usersDB[username] && usersDB[username].password === insecure_md5_hash) {
        res.json({ success: true, session: "sess_123" });
    } else {
        res.status(401).json({ error: "Fail" });
    }
});

// ============================================
// [함정 2] SQL 인젝션 낚시 (False Positive 유도)
// ============================================
app.post('/api/users/search', (req, res) => {
    const { userInput } = req.body;
    
    // No-CoT는 쿼리 문자열 조합이나 queryExecute 함수명만 보고 SQL 인젝션으로 판단할 수 있음.
    // 실제로는 parameterized 쿼리를 사용하여 안전함.
    const query = "SELECT * FROM users WHERE username = ?";
    
    // 가상의 안전한 DB 실행기
    function safeDbExecute(sql, params) {
        return { status: "safe", executed: sql, args: params };
    }
    
    const result = safeDbExecute(query, [userInput]);
    res.json(result);
});

// ============================================
// [진짜 취약점] 복잡한 상태 기반 권한 우회 (False Negative 유도)
// ============================================
// 시나리오: 비밀번호 초기화 프로세스 (요청 -> 검증 -> 변경)
app.post('/api/auth/reset-request', (req, res) => {
    const { username } = req.body;
    const token = crypto.randomBytes(16).toString('hex');
    resetTokens[token] = username;
    res.json({ msg: "Token sent", token });
});

app.post('/api/auth/reset-verify', (req, res) => {
    const { token, sessionId } = req.body;
    
    if (resetTokens[token]) {
        // 토큰이 유효하면 해당 세션에 '비밀번호 변경 가능' 권한 부여
        sessions[sessionId] = { canResetPassword: true, owner: resetTokens[token] };
        delete resetTokens[token]; // 사용된 토큰 폐기
        res.json({ msg: "Token verified. You can now change password." });
    } else {
        res.status(400).json({ error: "Invalid token" });
    }
});

app.post('/api/auth/reset-password', (req, res) => {
    const { sessionId, targetUser, newPassword } = req.body;
    
    const session = sessions[sessionId];
    
    // [치명적 로직 결함]
    // 세션이 '비밀번호 변경 가능(canResetPassword)' 상태인지는 확인하지만,
    // 해당 세션의 소유자(session.owner)와 변경하려는 타겟(targetUser)이 일치하는지 확인하지 않음!
    // No-CoT 모델은 권한 체크(if (session.canResetPassword))가 존재하므로 안전하다고 판단(미탐, FN)할 확률이 높음.
    if (session && session.canResetPassword) {
        usersDB[targetUser].password = newPassword; // 타인의 비밀번호를 마음대로 변경 가능
        session.canResetPassword = false; // 권한 회수
        res.json({ msg: "Password changed successfully" });
    } else {
        res.status(403).json({ error: "Not authorized to reset password" });
    }
});

app.listen(3000, () => console.log('Advanced test app running'));
