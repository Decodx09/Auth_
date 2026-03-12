require('dotenv').config();
const express = require('express');
const app = express();
const PORT = process.env.PORT || 8080;

// The main page
app.get('/', (req, res) => {
    res.send('Hello EKS! The Load Balancer is working.');
});

// The health check endpoint
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});