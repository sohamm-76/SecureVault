// ─── Core domain types for SecureVault ───────────────────────────────────────
// Every scanner consumes ScanTarget and produces Vulnerability[].
// The reporter consumes ScanResult.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ScanTarget {
  baseUrl: string;          // e.g. "http://localhost:3000"
  endpoints?: string[];     // optional: specific paths to test
  headers?: Record<string, string>; // auth tokens etc. for authenticated scans
  timeout?: number;         // ms per request, default 5000
}

export interface Vulnerability {
  id: string;               // e.g. "API1:2023"
  name: string;             // e.g. "Broken Object Level Authorization"
  severity: Severity;
  endpoint: string;         // which endpoint triggered this
  description: string;      // what was found
  evidence: string;         // raw proof: status codes, response snippets
  remediation: string;      // concrete fix suggestion
}

export interface ScanResult {
  target: string;
  scannedAt: string;        // ISO timestamp
  duration: number;         // ms
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface Scanner {
  id: string;
  name: string;
  description: string;
  run(target: ScanTarget): Promise<Vulnerability[]>;
}