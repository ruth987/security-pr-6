const express = require('express');
const cors = require('cors');
require('dotenv').config();
const pool = require('./db/config');
const Logger = require('./services/logger'); // Add this

const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const userRoutes = require('./routes/user');

const app = express();

app.use(cors());
app.use(express.json());

// Add logging middleware
app.use(async (req, res, next) => {
    try {
        await Logger.logUserActivity(
            req.user?.id || null,
            'http_request',
            {
                method: req.method,
                path: req.path,
                body: req.method !== 'GET' ? req.body : undefined
            },
            req
        );
    } catch (error) {
        console.error('Middleware logging error:', error);
    }
    next();
});

// Test route for logger
app.get('/test-logger', async (req, res) => {
    try {
        await Logger.logSystemEvent('info', 'test_event', {
            message: 'Testing logger'
        });
        res.json({ message: 'Logger test completed' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Routes
app.use('/auth', authRoutes);
app.use('/admin', adminRoutes);
app.use('/user', userRoutes);

// Log system startup
Logger.logSystemEvent('info', 'system_startup', {
    timestamp: new Date(),
    environment: process.env.NODE_ENV
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});