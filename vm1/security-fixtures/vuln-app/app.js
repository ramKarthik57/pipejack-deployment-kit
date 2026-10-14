const express = require('express');
const app = express();
const port = 3000;

app.get('/', (req, res) => {
  res.send('<h1>Employee Management System</h1>');
});

app.get('/employees', (req, res) => {
  res.json([{id:1, name:'Alice'}, {id:2, name:'Bob'}]);
});

app.listen(port, () => console.log(`App listening on port ${port}`));
