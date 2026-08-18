const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const QRCode = require('qrcode');

const app = express();
app.use(cors());
app.use(express.json());

// 1. Pull secret from Railway environment variables, fallback to local string for testing
const JWT_SECRET = process.env.JWT_SECRET || 'KJVITE-SECRET';

// 2. Point SQLite to Railway's persistent volume path if it exists, otherwise use local path
const DB_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || '.';
const DB_PATH = path.join(DB_DIR, 'wedding.db');

// Initialize SQLite Database (better-sqlite3 is fully synchronous)
const db = new Database(DB_PATH, { verbose: console.log });

// Create Tables
db.exec(`CREATE TABLE IF NOT EXISTS guests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    status TEXT DEFAULT 'pending'
)`);

db.exec(`CREATE TABLE IF NOT EXISTS admin (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
)`);

try {
    // Replace 'plus_ones' and 'INTEGER DEFAULT 0' with your desired column name and type
    db.exec(`ALTER TABLE guests ADD COLUMN tableNo INTEGER DEFAULT 0`);
} catch (err) {
    // SQLite throws an error if the column already exists; we catch and ignore it
    if (!err.message.includes('duplicate column name')) {
        console.error("Failed to alter table:", err.message);
    }
}

// Seed default admin if empty (Username: admin, Password: password123)
const adminExists = db.prepare('SELECT 1 FROM admin WHERE username = ?').get('admin');
if (!adminExists) {
    const hash = bcrypt.hashSync('password123', 10);
    db.prepare('INSERT INTO admin (username, password) VALUES (?, ?)').run('admin', hash);
}

// --- API ENDPOINTS ---

// 0. Health check
app.get('/', (req, res) => {
    res.send('Connected to the server!');
});

// 1. Get single guest details
app.get('/api/guests/:token', (req, res) => {
    const row = db.prepare('SELECT * FROM guests WHERE token = ?').get(req.params.token);
    if (!row) return res.status(404).json({ error: 'Invitation not found' });
    res.json(row);
});

// 2. RSVP Update
app.post('/api/guests/:token/rsvp', (req, res) => {
    const { status } = req.body;
    if (!['accepted', 'rejected', 'pending'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }
    try {
        db.prepare('UPDATE guests SET status = ? WHERE token = ?').run(status, req.params.token);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. Admin Login
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    const row = db.prepare('SELECT * FROM admin WHERE username = ?').get(username);
    if (!row || !bcrypt.compareSync(password, row.password)) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
});

// Middleware to protect admin routes
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// 4. Admin: Get all guests
app.get('/api/admin/guests', authenticateToken, (req, res) => {
    const rows = db.prepare('SELECT * FROM guests').all();
    res.json(rows);
});

// 5. Admin: Add a new guest
app.post('/api/admin/guests', authenticateToken, (req, res) => {
    const { name } = req.body;
    const token = Math.random().toString(36).substring(2, 9);
    try {
        const result = db.prepare('INSERT INTO guests (token, name) VALUES (?, ?)').run(token, name);
        res.json({ id: result.lastInsertRowid, token, name, status: 'pending' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. Admin: Delete a guest
app.delete('/api/admin/guests/:id', authenticateToken, (req, res) => {
    try {
        const result = db.prepare('DELETE FROM guests WHERE id = ?').run(req.params.id);
        if (result.changes === 0) return res.status(404).json({ error: 'Guest not found' });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 7. Admin: Update a guest name
app.patch('/api/admin/guests/:id', authenticateToken, (req, res) => {
    const { name, tableNo } = req.body;
    if (!name || !name.trim()) {
        return res.status(400).json({ error: 'Name is required' });
    }
    try {
        const result = db.prepare('UPDATE guests SET name = ?, tableNo = ? WHERE id = ?').run(name.trim(), tableNo || '', req.params.id);
        if (result.changes === 0) return res.status(404).json({ error: 'Guest not found' });
        res.json({ success: true, id: req.params.id, name: name.trim(), tableNo: tableNo || '' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// 8. Admin: Generate QR Code for a guest
app.get('/api/guests/:token/qrcode', async (req, res) => {
    const { token } = req.params;

    // 1. Verify that the guest exists in SQLite
    const guest = db.prepare('SELECT name FROM guests WHERE token = ?').get(token);
    if (!guest) {
        return res.status(404).json({ error: 'Guest not found' });
    }

    try {
        // 2. Define the payload for the QR code (URL to guest page or raw token)
        // Adjust the base URL to match your frontend deployment URL if needed
        const qrContent = token; 

        // 3. Generate PNG buffer
        const qrBuffer = await QRCode.toBuffer(qrContent, {
            type: 'png',
            width: 300,
            margin: 2,
            color: {
                dark: '#000000',
                light: '#ffffff'
            }
        });

        // 4. Set headers to prompt a file download on the browser
        const safeName = guest.name.replace(/[^a-z0-9]/gi, '_').toLowerCase();
        res.setHeader('Content-Type', 'image/png');
        res.setHeader('Content-Disposition', `attachment; filename="qrcode-${safeName}.png"`);

        // 5. Stream the buffer back as response
        res.send(qrBuffer);
    } catch (err) {
        res.status(500).json({ error: 'Failed to generate QR code' });
    }
});
app.get('/api/guests/reset/tableNo', async (req, res) => {
    try {
        const result = db.prepare('UPDATE guests SET tableNo = NULL').run();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Bind to Railway's dynamic port, using 3000 as a fallback for your local computer
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));