const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json()); // was express() - this is what parses req.body
app.get('/', (req, res) => {
    res.send('Ngilo API is running.');
});

const db = new sqlite3.Database('./ngilo.db', (err) => {
    if (err) {
        console.error('Error connecting to the database:', err.message);
    } else {
        console.log('Connected to the ngilo.db database.');
    }
});

db.serialize(() => {
    db.run(
        `CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        )`,
        (err) => {
            if (err) console.error('Error creating users table:', err.message);
        }
    );

    // table name fixed: "messages" (was "mesages")
    db.run(
        `CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )`,
        (err) => {
            if (err) console.error('Error creating messages table:', err.message);
        }
    );
});

// Register (frontend calls /api/register)
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = uuidv4();

        db.run(
            `INSERT INTO users (user_id, username, password) VALUES (?, ?, ?)`, // was "user"
            [userId, username, hashedPassword],
            function (err) {
                if (err) {
                    console.error(err.message);
                    return res.status(400).json({ message: 'Username already exists.' });
                }
                res.status(200).json({ userId, username });
            }
        );
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ message: 'Server error during signup.' });
    }
});

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ message: 'Server error during login.' });
        }
        if (!user) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        res.status(200).json({ userId: user.user_id, username: user.username });
    });
});

// Get a user's username (Home.jsx calls /api/user/:userId)
app.get('/api/user/:userId', (req, res) => {
    const { userId } = req.params;

    db.get('SELECT username FROM users WHERE user_id = ?', [userId], (err, user) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ message: 'Server error.' });
        }
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        res.status(200).json({ username: user.username });
    });
});

// Send an anonymous message
app.post('/api/messages', (req, res) => {
    const { recipientId, message } = req.body; // typo fixed (was reecipientId)
    if (!recipientId || !message) {
        return res.status(400).json({ message: 'Recipient ID and message are required.' });
    }

    db.get('SELECT user_id FROM users WHERE user_id = ?', [recipientId], (err, row) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({ message: 'Server error.' });
        }
        if (!row) {
            return res.status(404).json({ message: 'User not found.' });
        }

        db.run(
            `INSERT INTO messages (user_id, message) VALUES (?, ?)`,
            [recipientId, message],
            (err) => {
                if (err) {
                    console.error(err.message);
                    return res.status(500).json({ message: 'Failed to send message.' });
                }
                res.status(200).json({ message: 'Message sent successfully.' });
            }
        );
    });
});

// Get a user's inbox
app.get('/api/messages/:userId', (req, res) => {
    const { userId } = req.params;

    db.all(
        `SELECT id, message, timestamp FROM messages WHERE user_id = ? ORDER BY timestamp DESC`,
        [userId],
        (err, rows) => {
            if (err) {
                console.error(err.message);
                return res.status(500).json({ message: 'Failed to retrieve messages.' });
            }
            res.status(200).json(rows);
        }
    );
});

// Delete a message (only if it belongs to the user asking)
app.delete('/api/messages/:id', (req, res) => {
    const { id } = req.params;
    const { userId } = req.query;

    if (!userId) {
        return res.status(400).json({ message: 'User ID is required.' });
    }

    db.run(
        `DELETE FROM messages WHERE id = ? AND user_id = ?`,
        [id, userId],
        function (err) {
            if (err) {
                console.error(err.message);
                return res.status(500).json({ message: 'Failed to delete message.' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ message: 'Message not found.' });
            }
            res.status(200).json({ message: 'Message deleted.' });
        }
    );
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});