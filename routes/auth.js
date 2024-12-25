const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../db/config');
const { validatePassword } = require('../middleware/passwordPolicy');
const Logger = require('../services/logger');
const { authenticateToken } = require('../middleware/auth');

// Register with password policy
router.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate password
        const validation = validatePassword(password);
        if (!validation.isValid) {
            return res.status(400).json({ 
                error: "Invalid password",
                details: validation.errors
            });
        }

        // Hash password with salt
        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await pool.query(
            'INSERT INTO users (username, password, salt) VALUES ($1, $2, $3) RETURNING id',
            [username, hashedPassword, salt]
        );

        await Logger.logUserActivity(newUser.rows[0].id, 'user_registered', {
            username,
            timestamp: new Date()
        }, req);

        res.json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Login with account lockout
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.ip || req.connection.remoteAddress;

        console.log('Login attempt for username:', username); // Debug log

        // First, get the user
        const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        
        if (userResult.rows.length === 0) {
            console.log('User not found:', username);
            return res.status(401).json({ error: "User not found" });
        }

        const user = userResult.rows[0];
        console.log('User found, checking password...'); // Debug log

        // Record the login attempt BEFORE checking password
        try {
            const loginAttempt = await pool.query(
                'INSERT INTO login_attempts (user_id, ip_address, success) VALUES ($1, $2, $3) RETURNING *',
                [user.id, ip, false] // Initially set success to false
            );
            console.log('Login attempt recorded:', loginAttempt.rows[0]); // Debug log
        } catch (error) {
            console.error('Error recording login attempt:', error);
            // Continue with login process even if logging fails
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        console.log('Password valid:', validPassword); // Debug log

        if (!validPassword) {
            // Count failed attempts
            const attempts = await pool.query(
                `SELECT COUNT(*) FROM login_attempts 
                WHERE user_id = $1 
                AND success = false 
                AND attempt_time > NOW() - INTERVAL '15 minutes'`,
                [user.id]
            );

            const failedAttempts = parseInt(attempts.rows[0].count);
            console.log('Failed attempts:', failedAttempts); // Debug log

            if (failedAttempts >= 5) {
                // Lock the account
                try {
                    await pool.query(
                        `INSERT INTO account_lockouts (user_id, locked_until, reason) 
                        VALUES ($1, NOW() + INTERVAL '15 minutes', $2)`,
                        [user.id, 'Too many failed login attempts']
                    );
                    console.log('Account locked for user:', user.id); // Debug log
                } catch (error) {
                    console.error('Error locking account:', error);
                }

                return res.status(403).json({ 
                    error: "Account locked for 15 minutes due to too many failed attempts",
                    attemptsCount: failedAttempts
                });
            }

            return res.status(401).json({ 
                error: "Invalid password",
                attemptsRemaining: 5 - failedAttempts
            });
        }

        // If password is valid, update the login attempt to success
        try {
            await pool.query(
                'UPDATE login_attempts SET success = true WHERE user_id = $1 AND attempt_time = (SELECT MAX(attempt_time) FROM login_attempts WHERE user_id = $1)',
                [user.id]
            );
        } catch (error) {
            console.error('Error updating login attempt success:', error);
        }

        // Generate token and complete login
        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ token });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: error.message });
    }
});
// Change password
router.post('/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        // Validate new password
        const validation = validatePassword(newPassword);
        if (!validation.isValid) {
            return res.status(400).json({ 
                error: "Invalid new password",
                details: validation.errors
            });
        }

        // Verify current password
        const user = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
        const validPassword = await bcrypt.compare(currentPassword, user.rows[0].password);

        if (!validPassword) {
            return res.status(401).json({ error: "Current password is incorrect" });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update password
        await pool.query(
            'UPDATE users SET password = $1, salt = $2 WHERE id = $3',
            [hashedPassword, salt, req.user.id]
        );

        await Logger.logUserActivity(req.user.id, 'password_changed', {
            timestamp: new Date()
        }, req);

        res.json({ message: "Password updated successfully" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;