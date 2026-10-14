const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

app.get('/', (req, res) => res.json({ status: 'ok', service: 'nodejs-app' }));
app.get('/health', (req, res) => res.json({ healthy: true }));

app.listen(port, () => console.log(`listening on ${port}`));
