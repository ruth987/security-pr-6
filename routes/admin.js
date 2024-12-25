const express = require('express');
const router = express.Router();
const pool = require('../db/config');
const { authenticateToken, authorizeRole } = require('../middleware/auth');
const Logger = require('../services/logger');


// Get all users
router.get('/users', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const users = await pool.query('SELECT id, username, role FROM users');
        res.json(users.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Change user role
router.put('/users/:userId/role', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const { userId } = req.params;
        const { newRole, reason } = req.body;

        // Log the role change attempt
        await Logger.logUserActivity(req.user.id, 'role_change_attempt', {
            target_user: userId,
            new_role: newRole,
            reason
        }, req);
        
        console.log("here 1")
        // Get current role
        const currentUser = await pool.query('SELECT role FROM users WHERE id = $1', [userId]);
        const oldRole = currentUser.rows[0].role;
        console.log("here 2")

        // Update role
        await pool.query('UPDATE users SET role = $1 WHERE id = $2', [newRole, userId]);
        console.log("here 3")

        // Create audit trail
        await pool.query(
            'INSERT INTO role_audit (user_id, old_role, new_role, changed_by, reason) VALUES ($1, $2, $3, $4, $5)',
            [userId, oldRole, newRole, req.user.id, reason]
        );
        console.log("here 4")
        await Logger.logUserActivity(req.user.id, 'role_change_success', {
            target_user: userId,
            old_role: oldRole,
            new_role: newRole
        }, req);

        res.json({ message: "Role updated successfully" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete user
router.delete('/users/:userId', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const { userId } = req.params;
        await pool.query('DELETE FROM users WHERE id = $1', [userId]);
        res.json({ message: "User deleted successfully" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// View audit trail
router.get('/audit-trail', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const auditTrail = await pool.query(`
            SELECT 
                ra.id,
                u1.username as changed_user,
                ra.old_role,
                ra.new_role,
                u2.username as changed_by,
                ra.changed_at,
                ra.reason
            FROM role_audit ra
            JOIN users u1 ON ra.user_id = u1.id
            JOIN users u2 ON ra.changed_by = u2.id
            ORDER BY ra.changed_at DESC
        `);
        res.json(auditTrail.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;