const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

exports.signup = async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username: username, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "Utilisateur ajouté !" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res
        .status(401)
        .json({ message: "Utilisateur ou mot de passe incorrect" });
    }

    const isValid = await bcrypt.compare(password, user.password);

    if (!isValid) {
      return res
        .status(401)
        .json({ message: "Utilisateur ou mot de passe incorrect" });
    }

    const token = jwt.sign({ userId: user.id }, "RANDOM_TOKEN_SECRET", {
      expiresIn: "24h",
    });
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.profile = async (req, res) => {
  try {
   
    const userId = req.query.userId;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json("Utilisateur inconnu");
    }

    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
