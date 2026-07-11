import axios from "axios";
import { Scanner, ScanTarget, Vulnerability } from "../utils/types";

// How many requests we fire to test for rate limiting
const REQUEST_COUNT = 20;
// Endpoints worth testing — login/auth endpoints are the most critical
const DEFAULT_ENDPOINTS = ["/login", "/auth", "/token", "/api/login", "/users"];

export const rateLimitScanner: Scanner = {
  id: "API4:2023",
  name: "Unrestricted Resource Consumption",
  description: "Detects endpoints with no rate limiting by firing rapid repeated requests",

  async run(target: ScanTarget): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const endpoints = target.endpoints ?? DEFAULT_ENDPOINTS;
    const timeout = target.timeout ?? 5000;

    for (const endpoint of endpoints) {
      const url = `${target.baseUrl}${endpoint}`;
      const statusCodes: number[] = [];
      let got429 = false;

      // Fire REQUEST_COUNT requests as fast as possible (all in parallel)
      const requests = Array.from({ length: REQUEST_COUNT }, () =>
        axios
          .post(url, { email: "test@test.com", password: "wrongpassword" }, {
            timeout,
            headers: { "Content-Type": "application/json", ...target.headers },
            validateStatus: () => true, // don't throw on 4xx/5xx
          })
          .then(res => {
            statusCodes.push(res.status);
            if (res.status === 429) got429 = true;
          })
          .catch(() => {
            // endpoint doesn't exist or timed out — skip silently
          })
      );

      await Promise.all(requests);

      // Only report if endpoint actually exists (skip 404s and no-response)
      if (statusCodes.length === 0) continue;
      if (statusCodes.every(code => code === 404)) continue;

      if (!got429) {
        vulnerabilities.push({
          id: "API4:2023",
          name: "Unrestricted Resource Consumption — No Rate Limiting",
          severity: "high",
          endpoint: url,
          description:
            `Sent ${REQUEST_COUNT} rapid requests to ${endpoint} and never received a 429 (Too Many Requests). ` +
            `This endpoint is vulnerable to brute-force and denial-of-service attacks.`,
          evidence: `Status codes received: [${[...new Set(statusCodes)].join(", ")}]. No 429 observed.`,
          remediation:
            "Add rate limiting middleware (e.g. express-rate-limit). " +
            "Recommended: max 5 requests per minute on auth endpoints. " +
            "Also consider account lockout after N failed attempts.",
        });
      }
    }

    return vulnerabilities;
  },
};