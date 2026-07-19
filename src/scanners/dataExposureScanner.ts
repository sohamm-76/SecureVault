import axios from "axios";
import { Scanner, ScanTarget, Vulnerability } from "../utils/types";

// Sensitive field names that should never appear in API responses
const SENSITIVE_FIELDS = [
  "password",
  "passwordHash",
  "password_hash",
  "hash",
  "secret",
  "apiKey",
  "api_key",
  "token",
  "accessToken",
  "access_token",
  "refreshToken",
  "refresh_token",
  "ssn",
  "creditCard",
  "credit_card",
  "cvv",
  "privateKey",
  "private_key",
];

// Stack trace patterns in response body
const STACK_TRACE_PATTERNS = [
  /at\s+\w+\s+\(.*:\d+:\d+\)/,  // "at functionName (file:line:col)"
  /Error:.*\n\s+at/,              // "Error: msg \n at"
];

// Internal path patterns that shouldn't be exposed
const INTERNAL_PATH_PATTERNS = [
  /\/var\/app\//,
  /\/home\/\w+\//,
  /\/etc\//,
  /C:\\Users\\/,
  /\/root\//,
];

// Endpoints to check for data exposure
const DEFAULT_ENDPOINTS = [
  { path: "/users/1",  method: "GET" as const },
  { path: "/users/2",  method: "GET" as const },
  { path: "/profile",  method: "GET" as const },
  { path: "/me",       method: "GET" as const },
  { path: "/account",  method: "GET" as const },
  { path: "/orders/999", method: "GET" as const }, // intentionally invalid — triggers error
];

export const dataExposureScanner: Scanner = {
  id: "API3:2023",
  name: "Broken Object Property Level Authorization",
  description:
    "Scans API responses for leaked sensitive fields, stack traces, and internal paths",

  async run(target: ScanTarget): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const timeout = target.timeout ?? 5000;

    for (const { path, method } of DEFAULT_ENDPOINTS) {
      const url = `${target.baseUrl}${path}`;

      try {
        const res = await axios.request({
          method,
          url,
          timeout,
          headers: { ...target.headers },
          validateStatus: () => true, // don't throw on any status
        });

        const body = res.data;
        const bodyStr = JSON.stringify(body);

        // ── Check 1: Sensitive fields in response body ──────────────────────
        const foundFields = SENSITIVE_FIELDS.filter(field =>
          Object.keys(body ?? {}).some(
            key => key.toLowerCase() === field.toLowerCase()
          )
        );

        if (foundFields.length > 0) {
          vulnerabilities.push({
            id: "API3:2023",
            name: "Broken Object Property Level Auth — Sensitive Fields Exposed",
            severity: "high",
            endpoint: url,
            description:
              `${path} returns sensitive fields in its response that should never be sent to clients. ` +
              `This can lead to credential theft, account takeover, or data breach.`,
            evidence: `Sensitive fields found in response: ${foundFields.map(f => `"${f}"`).join(", ")}`,
            remediation:
              "Use a DTO (Data Transfer Object) pattern — only return fields explicitly allowlisted for the client. " +
              "Never return password hashes, tokens, or keys. " +
              "Use libraries like 'class-transformer' with @Exclude() decorators.",
          });
        }

        // ── Check 2: Stack trace in response ───────────────────────────────
        const hasStackTrace = STACK_TRACE_PATTERNS.some(pattern =>
          pattern.test(bodyStr)
        );

        if (hasStackTrace) {
          vulnerabilities.push({
            id: "API3:2023",
            name: "Security Misconfiguration — Stack Trace Exposed",
            severity: "medium",
            endpoint: url,
            description:
              `${path} returned a stack trace in the response body. ` +
              `Stack traces reveal internal file paths, function names, and code structure — ` +
              `all useful to an attacker mapping your system.`,
            evidence: `Stack trace pattern detected in response body from ${url}`,
            remediation:
              "Add a global error handler that returns only a generic error message to clients. " +
              "Log full stack traces server-side only. " +
              "In Express: never pass 'err.stack' in the response JSON.",
          });
        }

        // ── Check 3: Internal paths in response ────────────────────────────
        const exposedPath = INTERNAL_PATH_PATTERNS.find(pattern =>
          pattern.test(bodyStr)
        );

        if (exposedPath) {
          const match = bodyStr.match(exposedPath);
          vulnerabilities.push({
            id: "API3:2023",
            name: "Security Misconfiguration — Internal Path Exposed",
            severity: "medium",
            endpoint: url,
            description:
              `${path} leaks an internal server file path in its response. ` +
              `Attackers use this to understand your server layout for targeted attacks.`,
            evidence: `Internal path pattern detected: "${match?.[0]}" in response from ${url}`,
            remediation:
              "Sanitize all error messages before sending to clients. " +
              "Never include file system paths, database connection strings, or " +
              "internal hostnames in API responses.",
          });
        }

      } catch {
        // network error or timeout — skip
      }
    }

    return vulnerabilities;
  },
};