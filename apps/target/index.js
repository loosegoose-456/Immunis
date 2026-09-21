const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const app = express();
const port = 3001;

app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Initialize in-memory database
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )`);

    // Seed admin user
    db.run(`INSERT INTO users (username, password, role) VALUES ('admin', 'super_secret_unhackable_password_123', 'admin')`);
});

// Serve a basic HTML login form
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Vulnerable Origin Target</title>
            <style>
                body { font-family: system-ui, sans-serif; background: #111; color: #eee; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                .login-box { background: #222; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); border: 1px solid #333; }
                h2 { margin-top: 0; color: #ff4444; }
                input { display: block; width: 100%; margin-bottom: 1rem; padding: 0.5rem; background: #333; border: 1px solid #444; color: white; border-radius: 4px; box-sizing: border-box; }
                button { width: 100%; padding: 0.75rem; background: #ff4444; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
                button:hover { background: #ff6666; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>Admin Login</h2>
                <form action="/login" method="POST">
                    <label>Username</label>
                    <input type="text" name="username" placeholder="admin" required />
                    <label>Password</label>
                    <input type="password" name="password" placeholder="••••••••" required />
                    <button type="submit">Authenticate</button>
                </form>
            </div>
        </body>
        </html>
    `);
});

// The Vulnerable Endpoint (SQL Injection)
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // VULNERABILITY: Unsanitized raw string interpolation
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    console.log('[Origin] Executing query:', query);

    // MOCK VULNERABILITY EXTENSION: Allow non-SQLi attacks to "breach" the app for demo purposes
    const lowerUser = username.toLowerCase();
    const isXss = lowerUser.includes('<script') || lowerUser.includes('javascript:') || lowerUser.includes('onerror=');
    const isRce = lowerUser.includes(';/bin/') || lowerUser.includes('$(cd') || lowerUser.includes('|| cat ') || lowerUser.includes('&&');
    const isPathTraversal = lowerUser.includes('../') || lowerUser.includes('..\\') || lowerUser.includes('/etc/passwd');

    if (isXss || isRce || isPathTraversal) {
        console.log(`[Origin] Login SUCCESS via alternative mock exploit vector`);
        return res.status(200).json({
            success: true,
            message: 'Authentication bypassed (mock)',
            token: 'mock_admin_token_xyz_890',
            user: { username: 'admin', role: 'admin' }
        });
    }

    db.get(query, (err, row) => {
        if (err) {
            console.error('[Origin] DB Error:', err.message);
            return res.status(500).send('Internal Server Error');
        }

        if (row) {
            console.log(`[Origin] Login SUCCESS for user: ${row.username}`);
            return res.status(200).json({
                success: true,
                message: 'Authentication successful',
                token: 'mock_admin_token_xyz_890',
                user: row
            });
        } else {
            console.log('[Origin] Login FAILED');
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
    });
});

// Path Traversal Mock
app.get('/files', (req, res) => {
    const file = req.query.file || '';
    console.log('[Origin] Accessing file:', file);
    if (file.includes('passwd') || file.includes('../')) {
        return res.send('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n');
    }
    res.send(`File content of ${file}`);
});

// XSS Mock
app.get('/search', (req, res) => {
    const q = req.query.q || '';
    console.log('[Origin] Searching for:', q);
    // Unsafe reflection
    res.send(`<h1>Search Results for: ${q}</h1>`);
});

app.listen(port, () => {
    console.log(`[Origin] Vulnerable target running on http://localhost:${port}`);
});
