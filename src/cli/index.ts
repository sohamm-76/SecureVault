#!/usr/bin/env node
// SecureVault CLI — entry point
// Usage: securevault scan --url http://localhost:3000

import { Command } from "commander";

const program = new Command();

program
  .name("securevault")
  .description("Automated REST API vulnerability scanner — OWASP API Top 10")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a REST API for vulnerabilities")
  .requiredOption("-u, --url <url>", "Base URL of the API to scan")
  .option("-o, --output <format>", "Report format: json | html", "json")
  .option("-t, --timeout <ms>", "Request timeout in ms", "5000")
  .option("--verbose", "Show detailed output during scan")
  .action(async (options) => {
    console.log(`\n🔍 SecureVault — scanning ${options.url}\n`);
    // Scanners will be wired in here on Day 2
    console.log("✅ Scaffold ready. Scanners coming Day 2.");
  });

program.parse(process.argv);