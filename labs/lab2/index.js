const express = require('express');
const helmet = require('helmet');
const path = require('path');

const app = express();

// Utiliser Helmet pour configurer CSP
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["self"],
            scriptSrc: ["self", "https://cdnjs.cloudflare.com"],
            styleSrc: ["self", "https://cdnjs.cloudflare.com"],
            imgSrc: ["self"],
            reportUri: 'http://localhost:3001/report-violation',
        },
    },
}));

// Route pour les rapports de violations CSP
app.post('/report-violation', express.json(), (req, res) => {
    console.log('CSP Violation: ', req.body);
    res.status(204).end();
});

// Servir un fichier HTML statique
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Démarrer le serveur
const port = 3001;
app.listen(port, () => {
    console.log(`Serveur démarré sur le port ${port}`);
});