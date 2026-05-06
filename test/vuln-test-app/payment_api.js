const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

// 가상의 데이터베이스 (사용자 자산 정보)
let usersDB = {
    "admin": { passwordHash: "21232f297a57a5a743894a0e4a801fc3", balance: 5000000 }, // admin / admin 방치
    "user1": { passwordHash: "24c9e15e52afc47c225b757e7bee1f9d", balance: 10000 }
};

// ============================================
// [취약점 1] MD5 암호화 (ISMS-P 규약 위반 타겟)
// ============================================
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // ISMS-P 2.6.7 (암호연산) 위반: 취약한 해시 알고리즘 사용
    const hash = crypto.createHash('md5').update(password).digest('hex');

    if (usersDB[username] && usersDB[username].passwordHash === hash) {
        res.json({ success: true, token: `fake-jwt-token-for-${username}` });
    } else {
        res.status(401).json({ success: false, msg: "Invalid credentials" });
    }
});

// ============================================
// [취약점 2] eval() 사용 (Semgrep 정적 분석 규칙 타겟)
// ============================================
app.post('/api/eval', (req, res) => {
    const { mathFormula } = req.body;
    try {
        // 심각: 사용자의 입력값을 그대로 eval 에 넘김
        const result = eval(mathFormula);
        res.json({ result });
    } catch (e) {
        res.status(500).json({ error: "Calculation failed" });
    }
});

// ============================================
// [취약점 3] IDOR 및 논리 오류 (Agent 심층 추론 타겟)
// ============================================
app.post('/api/transfer', (req, res) => {
    // 세션에서 인증된 사용자를 가져왔다고 가정
    const loggedInUser = req.headers['x-user-id']; 
    
    const { fromAccount, toAccount, amount } = req.body;

    // 결함 A (Broken Access Control): 
    // 로그인된 사람(loggedInUser)과 출금 계좌(fromAccount)가 일치하는지 확인하지 않음!
    // -> 악의적 사용자가 타인의 계좌번호를 fromAccount 에 넣어 돈을 빼갈 수 있음.
    
    // 결함 B (Logic Bypass):
    // amount(금액)가 음수인지 판별하지 않음!
    // -> amount를 -10000으로 보내면 오히려 fromAccount는 돈이 증가하고 toAccount는 감소함.

    if (!usersDB[fromAccount] || !usersDB[toAccount]) {
        return res.status(404).json({ error: "Account not found" });
    }

    if (usersDB[fromAccount].balance < amount) {
        return res.status(400).json({ error: "Insufficient balance" });
    }

    // 이체 수행
    usersDB[fromAccount].balance -= amount;
    usersDB[toAccount].balance += amount;

    res.json({ 
        success: true, 
        msg: "Transfer complete", 
        remainingBalance: usersDB[fromAccount].balance 
    });
});


app.listen(3000, () => {
    console.log('App running on port 3000');
});
