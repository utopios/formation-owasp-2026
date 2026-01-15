const express = require('express'); 

const helmet = require('helmet');
const app = express();
const port = 3001;

// Use Helmet to set Content Security Policy
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'https://trusted.cdn.com'],
        styleSrc: ["'self'", 'https://trusted.cdn.com'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", 'https://trusted.cdn.com'],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
    },
  })
);

app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>CSP Example</title>
        <script src="https://trusted.cdn.com/script.js"></script>
        <link rel="stylesheet" href="https://trusted.cdn.com/styles.css">
      </head>
      <body>
        <h1>Hello, World!</h1>
        <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA" alt="Example Image">
        </body>
        </html>
    `);
    });

app.listen(port, () => {
  console.log(`CSP example app listening at http://localhost:${port}`);
});