const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const session = require("express-session");
require("dotenv").config();
const app = express();
const db = new Database("users.db");
db.exec(`CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREME
name TEXT  NOT NULL,
email TEXT NOT NULL UNIQUE,
phone TEXT NOT NULL,
password TEXT NOT NULL,
referral TEXT,
balance REAL DEFAULT 10.0,
is_premium INTEGER DEFAULT 0,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP
 )
`);
app.use(express.json());
app.use(express.static("public"));
app.use(session({
 secret: process.env.SESSION_SECRET || "change-this-development-secret",
 resave: false,
 saveUninitialized: false,
 cookie: {
 httpOnly: true,
 sameSite: "lax",
 secure: false,
 maxAge: 1000 * 60 * 60 * 24
 }
}));
// REGISTER USER
app.post("/api/register", async (req, res) => {
 try {
 const { name, email, phone, password, referral } = req.body;
 if (!name || !email || !phone || !password) {
 return res.status(400).json({ message: "Please fill in all required fields." });
 }
 if (password.length < 8) {
 return res.status(400).json({ message: "Password must have at least 8 characters." });
 }
 const existingUser = db.prepare(
 "SELECT id FROM users WHERE email = ?"
 ).get(email.trim().toLowerCase());
 if (existingUser) {
 return res.status(409).json({ message: "This email is already registered." });
 }
 const hashedPassword = await bcrypt.hash(password, 12);
 const result = db.prepare(`
 INSERT INTO users (name, email, phone, password, referral)
 VALUES (?, ?, ?, ?, ?)
 `).run(
 name.trim(),
 email.trim().toLowerCase(),
 phone.trim(),
 hashedPassword,
 referral || ""
 );
 res.status(201).json({
 message: "Account created successfully!",
 userId: result.lastInsertRowid
 });
 } catch (error) {
 console.error(error);
 res.status(500).json({ message: "Registration failed. Try again." });
 }
});
// LOGIN USER
app.post("/api/login", async (req, res) => {
 try {
 const { email, password } = req.body;
 if (!email || !password) {
 return res.status(400).json({ message: "Enter your email and password." });
 }
 const user = db.prepare(
 "SELECT * FROM users WHERE email = ?"
 ).get(email.trim().toLowerCase());
 if (!user) {
 return res.status(401).json({ message: "Invalid email or password." });
 }
 const passwordMatch = await bcrypt.compare(password, user.password);
 if (!passwordMatch) {
 return res.status(401).json({ message: "Invalid email or password." });
 }
 req.session.userId = user.id;
return res.json({
           success:true,
           message: "Login successful!",
    user:{
           name: user.name,
           balance:user.balance,
           isPremium:user.is_premium
  }
    }); catch (error) {
 console.error(error);
 res.status(500).json({ message: "Login failed." });
 }
});
// CHECK LOGGED-IN USER
app.get("/api/me", (req, res) => {
 if (!req.session.userId) {
 return res.status(401).json({ message: "Please log in." });
 }
 const user = db.prepare(
 "SELECT id, name, email, phone FROM users WHERE id = ?"
 ).get(req.session.userId);
 if (!user) {
 return res.status(401).json({ message: "User not found." });
 }
 res.json(user);
});
// LOGOUT
app.post("/api/logout", (req, res) => {
 req.session.destroy(() => {
 res.json({ message: "Logged out successfully." });
 });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
 console.log(`Server running at http://localhost:${PORT}`);
});
