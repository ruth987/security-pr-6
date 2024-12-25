const pool = require('../db/config');
const crypto = require('crypto');
require('dotenv').config();

// Encryption key (store in .env)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; 
const IV_LENGTH = 16;

class Logger {
    // Encrypt sensitive data
    static encrypt(text) {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return Buffer.concat([iv, encrypted]);
    }

    // Decrypt sensitive data
    static decrypt(encrypted) {
        const iv = encrypted.slice(0, IV_LENGTH);
        const encryptedData = encrypted.slice(IV_LENGTH);
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedData);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    }

    // Log user activity
    static async logUserActivity(userId, actionType, details, req) {
        try {
            const ip = req.ip || req.connection.remoteAddress;
            const userAgent = req.headers['user-agent'];

            // Encrypt sensitive information
            const sensitiveData = JSON.stringify({
                ip_address: ip,
                user_agent: userAgent,
                ...details
            });
            const encryptedData = this.encrypt(sensitiveData);

            await pool.query(
                `INSERT INTO activity_logs 
                (user_id, action_type, action_details, ip_address, user_agent, encrypted_data)
                VALUES ($1, $2, $3, $4, $5, $6)`,
                [userId, actionType, details, ip, userAgent, encryptedData]
            );

            // Check for alerts
            await this.checkAlerts(actionType, userId);
        } catch (error) {
            console.error('Logging error:', error);
            // Log to external service like CloudWatch or ELK stack
            await this.logSystemEvent('error', 'logging_failure', { error: error.message });
        }
    }

    // Log system events
    static async logSystemEvent(severity, eventType, details) {
        try {
            await pool.query(
                `INSERT INTO system_logs (severity, event_type, event_details)
                VALUES ($1, $2, $3)`,
                [severity, eventType, details]
            );

            // For critical events, trigger immediate alert
            if (severity === 'critical') {
                await this.triggerAlert(eventType, details);
            }
        } catch (error) {
            console.error('System logging error:', error);
            // Fallback to console logging if database is unavailable
            console.error({
                severity,
                eventType,
                details,
                timestamp: new Date().toISOString()
            });
        }
    }

    // Check for alert conditions
    static async checkAlerts(actionType, userId) {
        try {
            // Get alert configuration
            const alertConfig = await pool.query(
                'SELECT * FROM alert_configs WHERE event_type = $1 AND is_active = true',
                [actionType]
            );

            if (alertConfig.rows.length > 0) {
                const config = alertConfig.rows[0];
                
                // Check threshold in time window
                const count = await pool.query(
                    `SELECT COUNT(*) FROM activity_logs 
                    WHERE action_type = $1 
                    AND user_id = $2 
                    AND created_at > NOW() - INTERVAL '1 minute' * $3`,
                    [actionType, userId, config.time_window]
                );

                if (count.rows[0].count >= config.threshold) {
                    await this.triggerAlert(actionType, {
                        user_id: userId,
                        count: count.rows[0].count,
                        threshold: config.threshold
                    });
                }
            }
        } catch (error) {
            console.error('Alert check error:', error);
        }
    }

    // Trigger alerts
    static async triggerAlert(eventType, details) {
        // Implement your alert mechanism here (email, SMS, Slack, etc.)
        console.log('ALERT:', { eventType, details });
        
        // Log the alert
        await this.logSystemEvent('critical', 'alert_triggered', {
            event_type: eventType,
            details
        });
    }
}

module.exports = Logger;