/**
 * ⚠️  VULNERABLE API — FOR DEVELOPMENT ONLY ⚠️
 *
 * This Express server is intentionally insecure.
 * It exists solely to give SecureVault a test target.
 * Never deploy this. Never put real data in it.
 *
 * OWASP flaws baked in:
 *  API1:2023 — Broken Object Level Authorization  → /users/:id (no ownership check)
 *  API2:2023 — Broken Authentication              → /admin (trivial bypass)
 *  API3:2023 — Broken Object Property Auth        → /profile (returns password hash)
 *  API4:2023 — Unrestricted Resource Consumption  → no rate limiting anywhere
 *  API8:2023 — Security Misconfiguration          → stack traces in errors, no CORS policy
 */

import express, { Request, Response, NextFunction } from "express";

const app = express();
app.use(express.json());

// ─── Fake database ────────────────────────────────────────────────────────────
const users = [
  { id: 1, name: "Alice",   email: "alice@example.com", role: "admin",  passwordHash: "$2b$10$fakehashalice" },
  { id: 2, name: "Bob",     email: "bob@example.com",   role: "user",   passwordHash: "$2b$10$fakehashbob" },
  { id: 3, name: "Charlie", email: "charlie@example.com", role: "user", passwordHash: "$2b$10$fakehashcharlie" },
];

const orders = [
  { id: 101, userId: 1, item: "Laptop",  amount: 1200 },
  { id: 102, userId: 2, item: "Mouse",   amount: 25 },
  { id: 103, userId: 3, item: "Monitor", amount: 400 },
];

// ─── Health check (clean endpoint — baseline for scanner) ────────────────────
app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", service: "vulnerable-api" });
});

// ─── API1: Broken Object Level Authorization ──────────────────────────────────
// Any user can fetch ANY user's data by changing the :id in the URL.
// Fix: check that req.user.id === req.params.id before returning data.
app.get("/users/:id", (req: Request, res: Response) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: "User not found" });
  // 🚨 Returns full object including passwordHash — also API3
  res.json(user);
});

// ─── API2: Broken Authentication ─────────────────────────────────────────────
// "Admin" route that accepts any token containing the word "admin".
// Fix: validate a signed JWT with proper claims.
app.get("/admin/dashboard", (req: Request, res: Response) => {
  const token = req.headers["authorization"] || "";
  // 🚨 Trivially bypassable: any string with "admin" passes
  if (token.includes("admin")) {
    return res.json({ message: "Welcome admin", users, orders });
  }
  res.status(401).json({ error: "Unauthorized" });
});

// ─── API3: Broken Object Property Level Auth ─────────────────────────────────
// Profile endpoint leaks sensitive fields (passwordHash, role) to the user.
// Fix: use a DTO / allowlist of fields to return.
app.get("/profile", (req: Request, res: Response) => {
  const userId = parseInt(req.headers["x-user-id"] as string) || 1;
  const user = users.find(u => u.id === userId);
  // 🚨 Returns everything, including passwordHash and role
  res.json(user);
});

// ─── API4: Unrestricted Resource Consumption (no rate limiting) ───────────────
// This login endpoint has no rate limiting — brute-force friendly.
// Fix: add express-rate-limit middleware.
app.post("/login", (req: Request, res: Response) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  // 🚨 No lockout, no throttle, no captcha
  if (!user || password !== "password123") {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  res.json({ token: "fake-token-admin-abc123", userId: user.id });
});

// ─── API8: Security Misconfiguration ─────────────────────────────────────────
// Full stack trace exposed on errors. No security headers.
// Fix: never send stack traces to clients; use helmet.js for headers.
app.get("/orders/:id", (req: Request, res: Response) => {
  const order = orders.find(o => o.id === parseInt(req.params.id));
  if (!order) {
    // 🚨 Leaks internal paths and stack trace
    const err = new Error(`Order ${req.params.id} not found in database`);
    return res.status(500).json({
      error: err.message,
      stack: err.stack,       // never do this in production
      internalPath: "/var/app/db/orders.json"
    });
  }
  res.json(order);
});

// ─── Catch-all error handler ──────────────────────────────────────────────────
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  // 🚨 Also leaks stack trace
  res.status(500).json({ error: err.message, stack: err.stack });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`\n⚠️  Vulnerable API running at http://localhost:${PORT}`);
  console.log("   Endpoints:");
  console.log("   GET  /health           ← clean baseline");
  console.log("   GET  /users/:id        ← API1: BOLA");
  console.log("   GET  /admin/dashboard  ← API2: Broken Auth");
  console.log("   GET  /profile          ← API3: Data Exposure");
  console.log("   POST /login            ← API4: No Rate Limit");
  console.log("   GET  /orders/:id       ← API8: Misconfiguration\n");
});

export default app;