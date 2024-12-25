const Logger = require('../services/logger');

const requestLogger = async (req, res, next) => {
    const startTime = Date.now();

    // Capture the original end function
    const originalEnd = res.end;

    // Override the end function
    res.end = async function(...args) {
        const duration = Date.now() - startTime;
        
        // Log the request
        await Logger.logUserActivity(
            req.user?.id || null,
            'http_request',
            {
                method: req.method,
                path: req.path,
                duration,
                status: res.statusCode,
                query: req.query,
                body: req.method !== 'GET' ? req.body : undefined
            },
            req
        );

        // Call the original end function
        originalEnd.apply(res, args);
    };

    next();
};

module.exports = requestLogger;