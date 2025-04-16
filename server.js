const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());

// Mock user database
const users = [];

// User registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user
    users.push({ username, password: hashedPassword });
    res.status(201).send('User registered!');
});

// User login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Find user
    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).send('User not found!');

    // Validate password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).send('Invalid password!');

    // Generate token
    const token = jwt.sign({ username: user.username }, 'secret_key', { expiresIn: '1h' });
    res.json({ token });
});

// Protected route
app.get('/protected', (req, res) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send('Access denied!');

    try {
        const decoded = jwt.verify(token, 'secret_key');
        res.send(`Welcome ${decoded.username}!`);
    } catch (err) {
        res.status(401).send('Invalid token!');
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});