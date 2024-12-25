const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const pool = require('../db/config');
const { validatePassword } = require('../middleware/passwordPolicy');
const Logger = require('../services/logger');
const { authenticateToken } = require('../middleware/auth');

// Register with password policy
router.post('/register', async (req, res) => {
    try {
        const { username, password, role = 'user'} = req.body;

        // Validate password
        const validation = validatePassword(password);
        if (!validation.isValid) {
            return res.status(400).json({ 
                error: "Invalid password",
                details: validation.errors
            });
        }

        // Check if username already exists
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE username = $1',
            [username]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({ 
                error: "Username already exists" 
            });
        }

        // Hash password with salt
        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await pool.query(
            'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id',
            [username, hashedPassword, role]
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

// Generate MFA setup
router.post('/mfa/setup', authenticateToken, async (req, res) => {
    try {
        // Generate secret
        const secret = speakeasy.generateSecret({
            name: `YourApp:${req.user.username}`
        });

        // Store secret in database
        await pool.query(
            'INSERT INTO user_mfa (user_id, secret_key) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET secret_key = $2, is_enabled = false',
            [req.user.id, secret.base32]
        );

        // Generate QR code
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);

        await Logger.logUserActivity(req.user.id, 'mfa_setup_initiated', {
            timestamp: new Date()
        }, req);

        res.json({
            message: "MFA setup initiated",
            secret: secret.base32,
            qrCode
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Verify and enable MFA
router.post('/mfa/verify', authenticateToken, async (req, res) => {
    try {
        const { token } = req.body;

        // Get user's secret
        const mfaResult = await pool.query(
            'SELECT secret_key FROM user_mfa WHERE user_id = $1',
            [req.user.id]
        );

        if (mfaResult.rows.length === 0) {
            return res.status(400).json({ error: "MFA not set up" });
        }

        // Verify token
        const verified = speakeasy.totp.verify({
            secret: mfaResult.rows[0].secret_key,
            encoding: 'base32',
            token: token,
            window: 2
        });
        console.log('Verification result:', verified);

        if (!verified) {
            return res.status(400).json({ 
                error: "Invalid MFA token",
                debug: {
                    receivedToken: token,
                    currentTime: new Date().toISOString()
                }
            });
        }

        // Enable MFA
        await pool.query(
            'UPDATE user_mfa SET is_enabled = true WHERE user_id = $1',
            [req.user.id]
        );

        await Logger.logUserActivity(req.user.id, 'mfa_enabled', {
            timestamp: new Date()
        }, req);

        res.json({ message: "MFA enabled successfully" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// login to handle MFA
router.post('/login', async (req, res) => {
    try {
        const { username, password, mfaToken } = req.body;
        const ip = req.ip || req.connection.remoteAddress;
        const MAX_ATTEMPTS = 5;
        const LOCKOUT_DURATION = 15;

        console.log('Login attempt:', { username, hasMfaToken: !!mfaToken });

        const lockoutCheck = await pool.query(
            `SELECT locked_until FROM account_lockouts 
             WHERE user_id = (SELECT id FROM users WHERE username = $1)
             AND locked_until > NOW()`,
            [username]
        );

        if (lockoutCheck.rows.length > 0) {
            return res.status(403).json({
                error: "Account is locked",
                lockedUntil: lockoutCheck.rows[0].locked_until,
                message: `Too many failed attempts. Try again after ${LOCKOUT_DURATION} minutes.`
            });
        }

        const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: "User not found" });
        }

        const user = userResult.rows[0];
        const recentAttempts = await pool.query(
            `SELECT COUNT(*) FROM login_attempts 
             WHERE user_id = $1 
             AND success = false 
             AND attempt_time > NOW() - INTERVAL '15 minutes'`,
            [user.id]
        );

        const failedAttempts = parseInt(recentAttempts.rows[0].count);
        console.log('Recent failed attempts:', failedAttempts);
        const validPassword = await bcrypt.compare(password, user.password);

        await pool.query(
            'INSERT INTO login_attempts (user_id, ip_address, success) VALUES ($1, $2, $3)',
            [user.id, ip, validPassword]
        );
        if (!validPassword) {
            // If this failure puts us at or over the limit, lock the account
            if (failedAttempts + 1 >= MAX_ATTEMPTS) {
                await pool.query(
                    `INSERT INTO account_lockouts (user_id, locked_until, reason) 
                     VALUES ($1, NOW() + INTERVAL '${LOCKOUT_DURATION} minutes', $2)`,
                    [user.id, 'Too many failed login attempts']
                );

                await Logger.logUserActivity(user.id, 'account_locked', {
                    reason: 'Too many failed login attempts',
                    ip_address: ip
                }, req);

                return res.status(403).json({
                    error: "Account locked",
                    message: `Too many failed attempts. Account locked for ${LOCKOUT_DURATION} minutes.`,
                    remainingAttempts: 0
                });
            }

            return res.status(401).json({ 
                error: "Invalid password",
                remainingAttempts: MAX_ATTEMPTS - (failedAttempts + 1)
            });
        }
        // Check if MFA is enabled
        const mfaResult = await pool.query(
            'SELECT is_enabled, secret_key FROM user_mfa WHERE user_id = $1',
            [user.id]
        );

        console.log('MFA status:', { 
            enabled: mfaResult.rows.length > 0 && mfaResult.rows[0].is_enabled,
            hasToken: !!mfaToken 
        }); 

        if (mfaResult.rows.length > 0 && mfaResult.rows[0].is_enabled) {
            // If MFA is enabled but no token provided
            if (!mfaToken) {
                return res.status(401).json({ 
                    error: "MFA token required",
                    requiresMfa: true
                });
            }

            // Verify MFA token with more options
            const verifyOptions = {
                secret: mfaResult.rows[0].secret_key,
                encoding: 'base32',
                token: mfaToken.toString(),
                window: 2 // Allow 1 interval before and after
            };

            console.log('Verifying token:', {
                receivedToken: mfaToken,
                tokenLength: mfaToken.toString().length,
                currentTime: new Date().toISOString()
            }); // Debug log

            const verified = speakeasy.totp.verify(verifyOptions);

            console.log('Token verification result:', verified); // Debug log

            if (!verified) {
                // Generate current valid token for debugging
                const currentToken = speakeasy.totp({
                    secret: mfaResult.rows[0].secret_key,
                    encoding: 'base32'
                });

                console.log('Debug info:', {
                    receivedToken: mfaToken,
                    expectedToken: currentToken, // Remove in production!
                    currentTime: new Date().toISOString()
                });

                return res.status(401).json({ 
                    error: "Invalid MFA token",
                    debug: {
                        receivedToken: mfaToken,
                        currentTime: new Date().toISOString()
                    }
                });
            }
        }

        // If we get here, both password and MFA (if enabled) are verified
        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        await Logger.logUserActivity(user.id, 'login_success', {
            ip_address: ip,
            mfa_used: mfaResult.rows.length > 0 && mfaResult.rows[0].is_enabled
        }, req);

        console.log('Login successful:', { 
            userId: user.id, 
            mfaUsed: mfaResult.rows.length > 0 && mfaResult.rows[0].is_enabled 
        }); // Debug log

        res.json({ 
            token,
            mfaEnabled: mfaResult.rows.length > 0 && mfaResult.rows[0].is_enabled
        });
    } catch (error) {
        console.error('Login error:', error); // Debug log
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