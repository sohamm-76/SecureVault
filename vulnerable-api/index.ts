import express, { Request, Response, NextFunction } from "express";

const app = express();
app.use(express.json());

const users = [
  { id: 1, name: "Alice",   email: "alice@example.com", role: "admin", passwordHash: "$2b$10$fakehashalice" },
  { id: 2, name: "Bob",     email: "bob@example.com",   role: "user",  passwordHash: "$2b$10$fakehashbob" },
  { id: 3, name: "Charlie", email: "charlie@example.com", role: "user", passwordHash: "$2b$10$fakehashcharlie" },
];

const orders = [
  { id: 101, userId: 1, item: "Laptop",  amount: 1200 },
  { id: 102, userId: 2, item: "Mouse",   amount: 25 },
  { id: 103, userId: 3, item: "Monitor", amount: 400 },
];

app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", service: "vulnerable-api" });
});

// API1: BOLA
app.get("/users/:id", (req: Request, res: Response) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json(user);
});

// API2: Broken Auth
app.get("/admin/dashboard", (req: Request, res: Response) => {
  const token = req.headers["authorization"] || "";
  if (token.includes("admin")) {
    return res.json({ message: "Welcome admin", users, orders });
  }
  res.status(401).json({ error: "Unauthorized" });
});

// API3: Data Exposure
app.get("/profile", (req: Request, res: Response) => {
  const userId = parseInt(req.headers["x-user-id"] as string) || 1;
  const user = users.find(u => u.id === userId);
  res.json(user);
});

// API4: No Rate Limiting
app.post("/login", (req: Request, res: Response) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user || password !== "password123") {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  res.json({ token: "fake-token-admin-abc123", userId: user.id });
});

// API8: Misconfiguration
app.get("/orders/:id", (req: Request, res: Response) => {
  const order = orders.find(o => o.id === parseInt(req.params.id));
  if (!order) {
    const err = new Error(`Order ${req.params.id} not found in database`);
    return res.status(500).json({
      error: err.message,
      stack: err.stack,
      internalPath: "/var/app/db/orders.json"
    });
  }
  res.json(order);
});

// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`\n⚠️  Vulnerable API running at http://localhost:${PORT}`);
  console.log("   GET  /health           ← clean baseline");
  console.log("   GET  /users/:id        ← API1: BOLA");
  console.log("   GET  /admin/dashboard  ← API2: Broken Auth");
  console.log("   GET  /profile          ← API3: Data Exposure");
  console.log("   POST /login            ← API4: No Rate Limit");
  console.log("   GET  /orders/:id       ← API8: Misconfiguration\n");
});

export default app;