/**
 * Scanner: Rate Limit Detection (API4:2023 — Unrestricted Resource Consumption)
 *
 * Strategy:
 *  1. Fire N rapid requests at an endpoint
 *  2. If we never receive a 429 (Too Many Requests), rate limiting is absent
 *  3. Record evidence: all response codes received
 *
 * This file gets implemented on Day 2.
 */

type ScanTarget = unknown;

type Vulnerability = unknown;

type Scanner = {
  id: string;
  name: string;
  description: string;
  run: (target: ScanTarget) => Promise<Vulnerability[]>;
};

export const rateLimitScanner: Scanner = {
  id: "API4:2023",
  name: "Unrestricted Resource Consumption",
  description: "Detects endpoints with no rate limiting by sending rapid repeated requests",

  async run(_target: ScanTarget): Promise<Vulnerability[]> {
    // TODO Day 2 — implement the hammer loop here
    console.log("Rate limit scanner: coming Day 2");
    return [];
  },
};