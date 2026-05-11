import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = path.dirname(scriptPath);
const repoRoot = path.resolve(scriptDir, "..");

const defaultOptions = {
  config: path.join(repoRoot, "scripts", "coverage-thresholds.json"),
  rustLcov: path.join(repoRoot, "artifacts", "rust-coverage.lcov"),
  pythonJson: path.join(repoRoot, "artifacts", "python-coverage.json"),
  typescriptSummary: path.join(repoRoot, "apps", "command-center", "coverage", "coverage-summary.json"),
  writeSummary: path.join(repoRoot, "artifacts", "coverage-threshold-summary.md"),
};

const options = parseArgs(process.argv.slice(2), defaultOptions);
const thresholds = readJson(options.config);

const rustEntries = readRustCoverage(options.rustLcov);
const pythonEntries = readPythonCoverage(options.pythonJson);
const typescriptEntries = readTypescriptCoverage(options.typescriptSummary);

const reports = [
  ...evaluateTargets("TypeScript", typescriptEntries, thresholds.typescript ?? []),
  ...evaluateTargets("Python", pythonEntries, thresholds.python ?? []),
  ...evaluateTargets("Rust", rustEntries, thresholds.rust ?? []),
];

writeSummary(options.writeSummary, reports);

const summaryText = reports
  .map((report) => {
    const relation = report.passed ? ">=" : "<";
    return `${report.status} ${report.language} ${report.name}: ${formatPercent(report.coverage)}% ${relation} ${formatPercent(report.threshold)}%`;
  })
  .join("\n");

console.log(summaryText);

const githubStepSummary = process.env.GITHUB_STEP_SUMMARY;
if (githubStepSummary) {
  fs.appendFileSync(githubStepSummary, `${fs.readFileSync(options.writeSummary, "utf8")}\n`);
}

const failed = reports.filter((report) => !report.passed);
if (failed.length > 0) {
  process.exitCode = 1;
}

function parseArgs(argv, defaults) {
  const parsed = { ...defaults };

  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    const value = argv[index + 1];

    if (key === "--") {
      continue;
    }

    if (key === "--config" && value) {
      parsed.config = resolveCliPath(value);
      index += 1;
      continue;
    }

    if (key === "--rust-lcov" && value) {
      parsed.rustLcov = resolveCliPath(value);
      index += 1;
      continue;
    }

    if (key === "--python-json" && value) {
      parsed.pythonJson = resolveCliPath(value);
      index += 1;
      continue;
    }

    if (key === "--typescript-summary" && value) {
      parsed.typescriptSummary = resolveCliPath(value);
      index += 1;
      continue;
    }

    if (key === "--write-summary" && value) {
      parsed.writeSummary = resolveCliPath(value);
      index += 1;
      continue;
    }

    throw new Error(`Unsupported argument: ${key}`);
  }

  return parsed;
}

function resolveCliPath(candidatePath) {
  return path.isAbsolute(candidatePath) ? candidatePath : path.resolve(repoRoot, candidatePath);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function readRustCoverage(filePath) {
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  const entries = [];

  let currentPath = null;
  let total = null;
  let covered = null;

  for (const line of lines) {
    if (line.startsWith("SF:")) {
      currentPath = normalizeRepoPath(line.slice(3).trim());
      total = null;
      covered = null;
      continue;
    }

    if (line.startsWith("LF:")) {
      total = Number(line.slice(3));
      continue;
    }

    if (line.startsWith("LH:")) {
      covered = Number(line.slice(3));
      continue;
    }

    if (line === "end_of_record") {
      if (currentPath && Number.isFinite(total) && Number.isFinite(covered)) {
        entries.push([currentPath, { total, covered }]);
      }

      currentPath = null;
      total = null;
      covered = null;
    }
  }

  return entries;
}

function readPythonCoverage(filePath) {
  const report = readJson(filePath);

  return Object.entries(report.files).map(([fileName, fileCoverage]) => [
    normalizeRepoPath(fileName),
    {
      total: fileCoverage.summary.num_statements,
      covered: fileCoverage.summary.covered_lines,
    },
  ]);
}

function readTypescriptCoverage(filePath) {
  const report = readJson(filePath);

  return Object.entries(report)
    .filter(([fileName]) => fileName !== "total")
    .map(([fileName, fileCoverage]) => [
      normalizeRepoPath(fileName),
      {
        total: fileCoverage.lines.total,
        covered: fileCoverage.lines.covered,
      },
    ]);
}

function normalizeRepoPath(filePath) {
  if (path.isAbsolute(filePath)) {
    return path.relative(repoRoot, filePath).split(path.sep).join("/");
  }

  return filePath.replace(/^\.\//, "").split(path.sep).join("/");
}

function evaluateTargets(language, entries, targets) {
  return targets.map((target) => {
    const matchedEntries = entries.filter(([fileName]) => fileName.startsWith(target.pathPrefix));

    if (matchedEntries.length === 0) {
      throw new Error(`${language} target ${target.name} did not match any files for prefix ${target.pathPrefix}`);
    }

    const totals = matchedEntries.reduce(
      (accumulator, [, coverage]) => {
        accumulator.total += coverage.total;
        accumulator.covered += coverage.covered;
        return accumulator;
      },
      { total: 0, covered: 0 },
    );

    const coverage = totals.total === 0 ? 100 : (totals.covered / totals.total) * 100;

    return {
      language,
      name: target.name,
      threshold: target.minimumLineCoverage,
      coverage,
      status: coverage >= target.minimumLineCoverage ? "PASS" : "FAIL",
      passed: coverage >= target.minimumLineCoverage,
    };
  });
}

function writeSummary(filePath, reports) {
  const lines = [
    "# Coverage Threshold Report",
    "",
    "| Language | Target | Coverage | Threshold | Status |",
    "|---|---|---:|---:|---|",
    ...reports.map(
      (report) => `| ${report.language} | ${report.name} | ${formatPercent(report.coverage)}% | ${formatPercent(report.threshold)}% | ${report.status} |`,
    ),
    "",
    "Thresholds come from scripts/coverage-thresholds.json.",
  ];

  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${lines.join("\n")}\n`);
}

function formatPercent(value) {
  return value.toFixed(2);
}