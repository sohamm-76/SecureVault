#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import { rateLimitScanner } from "../scanners/rateLimitScanner";
import { brokenAuthScanner } from "../scanners/brokenAuthScanner";
import { dataExposureScanner } from "../scanners/dataExposureScanner";
import { ScanTarget, ScanResult, Vulnerability } from "../utils/types";

const program = new Command();

program
  .name("aperture")
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
    const target: ScanTarget = {
      baseUrl: options.url.replace(/\/$/, ""), // strip trailing slash
      timeout: parseInt(options.timeout),
    };

    console.log(chalk.bold(`\n🔍 Aperture — scanning ${target.baseUrl}\n`));

    const startTime = Date.now();
    const allVulnerabilities: Vulnerability[] = [];

    // ── Run all scanners ──────────────────────────────────────────────────────
    const scanners = [rateLimitScanner, brokenAuthScanner, dataExposureScanner];

    for (const scanner of scanners) {
      process.stdout.write(chalk.gray(`  ⏳ Running: ${scanner.name} ...`));
      const found = await scanner.run(target);
      allVulnerabilities.push(...found);

      if (found.length === 0) {
        console.log(chalk.green(" ✓ clean"));
      } else {
        console.log(chalk.red(` ✗ ${found.length} issue(s) found`));
      }

      if (options.verbose) {
        for (const v of found) {
          console.log(chalk.yellow(`\n    [${v.severity.toUpperCase()}] ${v.name}`));
          console.log(chalk.gray(`    Endpoint : ${v.endpoint}`));
          console.log(chalk.gray(`    Evidence : ${v.evidence}`));
          console.log(chalk.gray(`    Fix      : ${v.remediation}\n`));
        }
      }
    }

    // ── Build result ──────────────────────────────────────────────────────────
    const duration = Date.now() - startTime;
    const result: ScanResult = {
      target: target.baseUrl,
      scannedAt: new Date().toISOString(),
      duration,
      vulnerabilities: allVulnerabilities,
      summary: {
        total:    allVulnerabilities.length,
        critical: allVulnerabilities.filter(v => v.severity === "critical").length,
        high:     allVulnerabilities.filter(v => v.severity === "high").length,
        medium:   allVulnerabilities.filter(v => v.severity === "medium").length,
        low:      allVulnerabilities.filter(v => v.severity === "low").length,
        info:     allVulnerabilities.filter(v => v.severity === "info").length,
      },
    };

    // ── Print summary ─────────────────────────────────────────────────────────
    console.log(chalk.bold(`\n── Scan complete (${duration}ms) ──────────────────`));
    console.log(`  Total issues : ${result.summary.total}`);
    if (result.summary.critical) console.log(chalk.red(`  Critical     : ${result.summary.critical}`));
    if (result.summary.high)     console.log(chalk.red(`  High         : ${result.summary.high}`));
    if (result.summary.medium)   console.log(chalk.yellow(`  Medium       : ${result.summary.medium}`));
    if (result.summary.low)      console.log(chalk.blue(`  Low          : ${result.summary.low}`));

    if (result.summary.total === 0) {
      console.log(chalk.green("\n  ✅ No vulnerabilities detected.\n"));
    } else {
      console.log(chalk.red(`\n  ⚠️  ${result.summary.total} vulnerability(s) found. Run with --verbose for details.\n`));
    }

    // ── Output report ─────────────────────────────────────────────────────────
    if (options.output === "json") {
      console.log(JSON.stringify(result, null, 2));
    }
  });

program.parse(process.argv);