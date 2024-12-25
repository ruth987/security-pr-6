router.get('/test-logging', async (req, res) => {
    try {
        // Test system log
        await Logger.logSystemEvent('info', 'test_event', {
            message: 'Testing logging system'
        });

        // Test user activity log
        await Logger.logUserActivity(1, 'test_action', {
            message: 'Testing user activity logging'
        }, req);

        res.json({ message: 'Logs created successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});