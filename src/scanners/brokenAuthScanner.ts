import axios from "axios";
import { Scanner, ScanTarget, Vulnerability } from "../utils/types";

// Common weak/garbage tokens real attackers try first
const WEAK_TOKENS = [
  "admin",
  "test",
  "Bearer null",
  "Bearer undefined",
  "Bearer ",
  "null",
  "undefined",
  "test123",
  "password",
  "secret",
  "token",
  "Bearer test",
  "Basic YWRtaW46YWRtaW4=", // base64 of admin:admin
];

// Endpoints that should be protected
const PROTECTED_ENDPOINTS = [
  "/admin",
  "/admin/dashboard",
  "/admin/users",
  "/dashboard",
  "/api/admin",
  "/users",
  "/profile",
  "/account",
  "/settings",
];

export const brokenAuthScanner: Scanner = {
  id: "API2:2023",
  name: "Broken Authentication",
  description:
    "Tests protected endpoints with weak/common tokens and checks for missing auth entirely",

  async run(target: ScanTarget): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const timeout = target.timeout ?? 5000;
    const endpoints = target.endpoints ?? PROTECTED_ENDPOINTS;

    for (const endpoint of endpoints) {
      const url = `${target.baseUrl}${endpoint}`;

      // ── Check 1: Is the endpoint completely unprotected? ──────────────────
      try {
        const res = await axios.get(url, {
          timeout,
          validateStatus: () => true,
        });

        if (res.status === 200) {
          vulnerabilities.push({
            id: "API2:2023",
            name: "Broken Authentication — Endpoint Requires No Auth",
            severity: "critical",
            endpoint: url,
            description: `${endpoint} returned 200 with no authentication header at all. This endpoint is completely unprotected.`,
            evidence: `GET ${url} (no auth header) → HTTP ${res.status}`,
            remediation:
              "Protect this endpoint with authentication middleware. " +
              "Validate a signed JWT on every request. " +
              "Return 401 for missing tokens and 403 for insufficient permissions.",
          });
          continue; // already wide open — no need to test weak tokens
        }
      } catch {
        continue; // endpoint unreachable — skip
      }

      // ── Check 2: Does a weak/garbage token get through? ───────────────────
      const bypassedBy: string[] = [];

      for (const token of WEAK_TOKENS) {
        try {
          const res = await axios.get(url, {
            timeout,
            headers: { Authorization: token },
            validateStatus: () => true,
          });

          if (res.status === 200) {
            bypassedBy.push(token);
          }
        } catch {
          // network error — skip this token
        }
      }

      if (bypassedBy.length > 0) {
        vulnerabilities.push({
          id: "API2:2023",
          name: "Broken Authentication — Weak Token Accepted",
          severity: "critical",
          endpoint: url,
          description:
            `${endpoint} accepted ${bypassedBy.length} weak/garbage token(s) as valid authentication. ` +
            `An attacker can gain unauthorized access without any credentials.`,
          evidence: `Tokens that bypassed auth: ${bypassedBy.map(t => `"${t}"`).join(", ")}`,
          remediation:
            "Replace token validation with proper JWT verification (use jsonwebtoken library). " +
            "Never check if a token 'contains' a keyword — always verify the signature. " +
            "Reject any token that fails cryptographic verification.",
        });
      }
    }

    return vulnerabilities;
  },
};