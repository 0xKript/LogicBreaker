// VULN: eval of a request value inside an arrow route handler (CWE-94).
const app = require('express')();
app.get('/calc', (req, res) => {
    eval(req.query.expr);
});
