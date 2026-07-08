const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path'); // Added for handling directory paths safely

const app = express();
app.use(cors());
app.use(express.json());

// 1. Pull secret from Railway environment variables, fallback to local string for testing
const JWT_SECRET = process.env.JWT_SECRET || 'KJVITE-SECRET'; 

// 2. Point SQLite to Railway's persistent volume path if it exists, otherwise use local path
const DB_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || '.';
const DB_PATH = path.join(DB_DIR, 'wedding.db');

// Initialize SQLite Database
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) console.error(err.message);
    console.log(`Connected to the SQLite database at: ${DB_PATH}`);
});

// Create Tables
db.serialize(() => {
    // Guests Table
    db.run(`CREATE TABLE IF NOT EXISTS guests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        status TEXT DEFAULT 'pending'
    )`);

    // Admin Table (Simple single-user setup)
    db.run(`CREATE TABLE IF NOT EXISTS admin (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL
    )`, () => {
        // Seed default admin if empty (Username: admin, Password: password123)
        const hash = bcrypt.hashSync('password123', 10);
        db.run(`INSERT OR IGNORE INTO admin (username, password) VALUES ('admin', ?)`, [hash]);
    });
});

// --- API ENDPOINTS ---

// 0. Health check
app.get('/', (req, res) => {
    res.send('Connected to the server!');
});

// 1. Get single guest details
app.get('/api/guests/:token', (req, res) => {
    db.get('SELECT * FROM guests WHERE token = ?', [req.params.token], (err, row) => {
        if (!row) return res.status(404).json({ error: 'Invitation not found' });
        res.json(row);
    });
});

// 2. RSVP Update
app.post('/api/guests/:token/rsvp', (req, res) => {
    const { status } = req.body; 
    if (!['accepted', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }
    db.run('UPDATE guests SET status = ? WHERE token = ?', [status, req.params.token], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// 3. Admin Login
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM admin WHERE username = ?', [username], (err, row) => {
        if (!row || !bcrypt.compareSync(password, row.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ token });
    });
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
    db.all('SELECT * FROM guests', [], (err, rows) => {
        res.json(rows);
    });
});

// 5. Admin: Add a new guest
app.post('/api/admin/guests', authenticateToken, (req, res) => {
    const { name } = req.body;
    const token = Math.random().toString(36).substring(2, 9); 
    db.run('INSERT INTO guests (token, name) VALUES (?, ?)', [token, name], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, token, name, status: 'pending' });
    });
});

// 6. Admin: Delete a guest
app.delete('/api/admin/guests/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM guests WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Guest not found' });
        res.json({ success: true });
    });
});

// 7. Admin: Update a guest name
app.patch('/api/admin/guests/:id', authenticateToken, (req, res) => {
    const { name } = req.body;
    if (!name || !name.trim()) {
        return res.status(400).json({ error: 'Name is required' });
    }
    db.run('UPDATE guests SET name = ? WHERE id = ?', [name.trim(), req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Guest not found' });
        res.json({ success: true, id: req.params.id, name: name.trim() });
    });
});

// 3. Bind to Railway's dynamic port, using 3000 as a fallback for your local computer
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));