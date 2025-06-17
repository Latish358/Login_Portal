const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const port = 3000;

// Middleware
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'your-secure-secret-key', // Replace with a strong secret
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true in production with HTTPS
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Serve static files
app.use('/Login', express.static(path.join(__dirname, 'Login')));
app.use('/Dashboard', express.static(path.join(__dirname, 'Dashboard')));

// PostgreSQL connection
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'Login_db',
    password: 'root',
    port: 5432
});

// Connect to database
pool.connect()
    .then(() => console.log('Connected to PostgreSQL database'))
    .catch(err => console.error('Database connection error:', err));

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/Login/index.html');
    }
};

// Helper function to validate email
const validateEmail = (email) => {
    if (!email.endsWith('@gmail.com')) return false;
    const localPart = email.split('@')[0];
    if (localPart.length < 3 || localPart.length > 30) return false;
    const validPattern = /^[a-zA-Z0-9]+([.-_]?[a-zA-Z0-9]+)*$/;
    if (!validPattern.test(localPart)) return false;
    if (/[.-_]{2,}/.test(localPart)) return false;
    return true;
};

// Helper function to validate password
const validatePassword = (password) => {
    const requirements = {
        length: /.{8,}/,
        uppercase: /[A-Z]/,
        lowercase: /[a-z]/,
        number: /[0-9]/,
        special: /[!@#$%^&*]/
    };
    return Object.values(requirements).every(regex => regex.test(password));
};

// Root route
app.get('/', (req, res) => {
    res.redirect('/Login/index.html');
});

// Signup route
app.post('/api/signup', async (req, res) => {
    const { username, email, password, confirmPassword, profileImage } = req.body;

    if (!username || !email || !password || !confirmPassword || !profileImage) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const usernameRegex = /^[A-Za-z]{5,}$/;
    if (!usernameRegex.test(username)) {
        return res.status(400).json({ error: 'Username must be at least 5 characters long and contain only letters' });
    }

    if (!validateEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!validatePassword(password)) {
        return res.status(400).json({ error: 'Password does not meet requirements' });
    }

    if (password !== confirmPassword) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    try {
        const userCheck = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ error: 'Email or username already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (username, email, password, profile_image, biometric_enabled) VALUES ($1, $2, $3, $4, $5)',
            [username, email, hashedPassword, profileImage, false]
        );

        res.status(201).json({ message: 'Registration successful' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login route
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        req.session.user = {
            username: user.username,
            profileImage: user.profile_image,
            biometric_enabled: user.biometric_enabled
        };

        res.status(200).json({
            message: 'Login successful, proceed to biometric authentication'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Forgot password route
app.post('/api/forgot-password', async (req, res) => {
    const { email, newPassword, confirmPassword } = req.body;

    if (!email || !newPassword || !confirmPassword) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    if (!validateEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!validatePassword(newPassword)) {
        return res.status(400).json({ error: 'Password does not meet requirements' });
    }

    if (newPassword !== confirmPassword) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Email not found' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);

        res.status(200).json({ message: 'Password updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Biometric authentication route
app.post('/api/biometric-auth', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    // Simulate biometric verification
    setTimeout(() => {
        // Update session to mark biometric as verified
        req.session.user.biometric_verified = true;
        res.status(200).json({ 
            message: 'Biometric authentication successful',
            redirect: '/Dashboard/index.html'
        });
    }, 2000);
});

// Dashboard route (protected)
app.get('/Dashboard/index.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'Dashboard', 'index.html'));
});

// Get current user
app.get('/api/current-user', (req, res) => {
    if (req.session.user) {
        res.status(200).json(req.session.user);
    } else {
        res.status(401).json({ error: 'Not logged in' });
    }
});

// Logout route
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.status(200).json({ 
            message: 'Logged out successfully',
            redirect: '/Login/index.html'
        });
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});