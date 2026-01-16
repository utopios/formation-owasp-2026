const express = require("express");
const mongoose = require("mongoose");
const authRoutes = require("./routes/authRoutes");

const app = express();
const port = 3000;

app.use(express.json()).use("/api/auth", authRoutes);

mongoose
  .connect("mongodb://localhost:27017/exercice_jwt")
  .then(() => console.log("Connecté à MongoDB"))
  .catch((err) => {
    console.error("Erreur lors de la connection à MongoDB", err.message);
  });

app.listen(port, () => {
  console.log(`http://localhost:${port}`);
});
