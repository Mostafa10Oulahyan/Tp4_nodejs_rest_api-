const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();
app.use(express.json())
;app.use(cors());

const JWT_SECRET = "ma_super_cle_ultra_secrete_2026";

// Stockage temporaire en mémoire
const users = [];

// ================= REGISTER =================
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "Tous les champs sont requis" });
  }

  if (users.find(user => user.email === email)) {
    return res.status(400).json({ error: "Email déjà utilisé" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, email, password: hashedPassword });

  res.status(201).json({ message: "Utilisateur créé avec succès" });
});

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(user => user.email === email);

  if (!user) {
    return res.status(401).json({ error: "Identifiants incorrects" });
  }

  const validPassword = await bcrypt.compare(password, user.password);

  if (!validPassword) {
    return res.status(401).json({ error: "Identifiants incorrects" });
  }

  const token = jwt.sign(
    { email: user.email },
    JWT_SECRET,
    { expiresIn: "1m" }
  );

  res.json({ token });
});

// ================= MIDDLEWARE JWT =================
const verifyToken = (req, res, next) => {
  const authHeader = req.header("Authorization");

  if (!authHeader) {
    return res.status(401).json({ error: "Accès interdit" });
  }

  try {
    const token = authHeader.split(" ")[1];
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ error: "Token invalide ou expiré" });
  }
};

// ================= PROFILE =================
app.get("/profile", verifyToken, (req, res) => {
  const user = users.find(user => user.email === req.user.email);

  if (!user) {
    return res.status(404).json({ error: "Utilisateur non trouvé" });
  }

  res.json({
    username: user.username,
    email: user.email
  });
});
app.get("/", (req, res) => {
  res.json({ ok: "good job" });
})
// ================= SERVER =================
app.listen(PORT, () => {
  console.log(`Serveur en écoute sur le port ${PORT}`);
});