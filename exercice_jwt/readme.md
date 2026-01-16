### Démarrer un mongodb

docker run -d --name mongodb -p 27017:27017 -v mongodbdata:/data/db mongo

## Installer les packages

npm install

## Démarrer l'application
node app.js

## Route pour s'enregistrer 

POST http://localhost:3000/api/auth/signup  {username:'', password:''}

## Route pour se connecter 
POST http://localhost:3000/api/auth/login  {username:'', password:''}
