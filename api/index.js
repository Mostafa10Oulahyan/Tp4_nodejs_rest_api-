const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const config = require("../config.json");
const { success, error } = require("../functions");

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = "ma_super_cle_ultra_secrete_2026";

// Stockage temporaire en mémoire
const users = [];

// Helper: Email validation
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// ================= ROOT =================
app.get("/", (req, res) => {
  res.json({
    message: "API JWT Authentication",
    version: "1.0.0",
    endpoints: {
      register: "POST /register",
      login: "POST /login",
      profile: "GET /profile (requires token)",
    },
  });
});

// ================= REGISTER =================
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: "Tous les champs sont requis" });
    }

    if (username.trim().length < 3) {
      return res
        .status(400)
        .json({
          error: "Le nom d'utilisateur doit contenir au moins 3 caractères",
        });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Email invalide" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ error: "Le mot de passe doit contenir au moins 6 caractères" });
    }

    if (users.find((user) => user.email === email)) {
      return res.status(400).json({ error: "Email déjà utilisé" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
    });

    res.status(201).json({
      message: "Utilisateur créé avec succès",
      user: { username: username.trim(), email: email.toLowerCase().trim() },
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Erreur serveur lors de l'inscription" });
  }
});

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email et mot de passe requis" });
    }

    const user = users.find(
      (user) => user.email === email.toLowerCase().trim(),
    );

    if (!user) {
      return res.status(401).json({ error: "Identifiants incorrects" });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: "Identifiants incorrects" });
    }

    const token = jwt.sign(
      { email: user.email, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" },
    );

    res.json({
      token,
      user: { username: user.username, email: user.email },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Erreur serveur lors de la connexion" });
  }
});

// ================= MIDDLEWARE JWT =================
const verifyToken = (req, res, next) => {
  const authHeader = req.header("Authorization");

  if (!authHeader) {
    return res.status(401).json({ error: "Accès interdit - Token manquant" });
  }

  try {
    const token = authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Format du token invalide" });
    }

    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expiré" });
    }
    res.status(401).json({ error: "Token invalide" });
  }
};

// ================= PROFILE =================
app.get("/profile", verifyToken, (req, res) => {
  try {
    const user = users.find((user) => user.email === req.user.email);

    if (!user) {
      return res.status(404).json({ error: "Utilisateur non trouvé" });
    }

    res.json({
      username: user.username,
      email: user.email,
    });
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// ================= 404 HANDLER =================
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint non trouvé" });
});

app.get("/",()=>{
    res.json({message:"Good job! API is working."});
});
// Export for Vercel serverless function
module.exports = app;
