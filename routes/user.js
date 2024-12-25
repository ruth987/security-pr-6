const express = require('express');
const router = express.Router();
const pool = require('../db/config');
const { authenticateToken } = require('../middleware/auth');

// Get user profile
router.get('/profile', authenticateToken, async (req, res) => {
    try {
        const user = await pool.query(
            'SELECT id, username, role FROM users WHERE id = $1',
            [req.user.id]
        );
        res.json(user.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Request role change
router.post('/request-role-change', authenticateToken, async (req, res) => {
    try {
        const { requestedRole, reason } = req.body;
        await pool.query(
            'INSERT INTO role_change_requests (user_id, requested_role, reason, status) VALUES ($1, $2, $3, $4)',
            [req.user.id, requestedRole, reason, 'pending']
        );
        res.json({ message: "Role change request submitted successfully" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;

