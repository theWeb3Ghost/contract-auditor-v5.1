/**
 * Static Analyzer Engine — CLI Entrypoint.
 *
 * Invoked by the Python orchestrator (`evolution_orchestrator.py`):
 *   npx tsx src/analyzer/index.ts --target <source.sol> --label <vuln_type> [--json]
 *
 * Runs the full zero-shot analysis pipeline:
 *   parse → CFG → taint → features → reasoner → hypotheses → vulnerabilities
 *
 * Outputs JSON to stdout with discovered vulnerabilities, hypothesis evaluations,
 * features, risk scores, and confidence.
 */

import { readFileSync, existsSync } from "fs";
import { resolve, relative } from "path";
import { Logger } from "../lib/logger.js";
import { ZeroShotVulnerabilityPredictor, createZeroShotPredictor } from "../analyzer/zero_shot/predictor.js";
import { FeatureExtractor } from "../analyzer/features/extractor.js";
import { SolidityParser } from "../analyzer/ast/parser.js";

const log = new Logger("analyzer-index");

// ===========================================================================
// CLI Argument Parser
// ===========================================================================

interface AnalyzerArgs {
  target: string;
  label?: string;
  json: boolean;
  verbose: boolean;
}

function parseArgs(argv: string[]): AnalyzerArgs {
  const args: AnalyzerArgs = { target: "", json: false, verbose: false };
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--target" || arg === "-t") {
      args.target = argv[++i] || "";
    } else if (arg === "--label" || arg === "-l") {
      args.label = argv[++i];
    } else if (arg === "--json" || arg === "-j") {
      args.json = true;
    } else if (arg === "--verbose" || arg === "-v") {
      args.verbose = true;
    }
  }
  return args;
}

// ===========================================================================
// Parse error extraction
// ===========================================================================

function extractParseError(sourceCode: string, contractName: string): { success: boolean; error?: string } {
  try {
    SolidityParser.parse(sourceCode, `${contractName}.sol`);
    return { success: true };
  } catch (err: any) {
    const msg = err?.message || err?.toString?.() || "Unknown parse error";
    // Try to extract line/column info
    let errorStr = msg.substring(0, 500);
    if (err.location) {
      errorStr += ` at line ${err.location.startLine || "?"}, column ${err.location.startColumn || "?"}`;
    }
    return { success: false, error: errorStr };
  }
}

// ===========================================================================
// Main Analysis Function
// ===========================================================================

interface AnalysisOutput {
  contractName: string;
  contractAddress: string | null;
  sourceFile: string;
  label: string | undefined;
  discoveredVulnerabilities: any[];
  hypothesisEvaluations: any[];
  features: any;
  riskScore: number;
  confidence: number;
  parseSuccess: boolean;
  parseError?: string;
  error?: string;
}

async function analyze(args: AnalyzerArgs): Promise<AnalysisOutput> {
  // Resolve target file path
  const targetPath = resolve(args.target);

  if (!existsSync(targetPath)) {
    return {
      contractName: args.target,
      contractAddress: null,
      sourceFile: args.target,
      label: args.label,
      discoveredVulnerabilities: [],
      hypothesisEvaluations: [],
      features: {},
      riskScore: 0,
      confidence: 0,
      parseSuccess: false,
      parseError: `File not found: ${targetPath}`,
      error: `File not found: ${targetPath}`,
    };
  }

  const sourceCode = readFileSync(targetPath, "utf-8");
  const contractName = targetPath.split("/").pop()?.replace(/\.sol$/, "") || "unnamed";
  const sourceFile = relative(process.cwd(), targetPath);

  // Step 1: Parse — check for parse errors first
  const parseCheck = extractParseError(sourceCode, contractName);
  if (!parseCheck.success) {
    log.warn(`Parse failed for ${contractName}: ${parseCheck.error}`);
    return {
      contractName,
      contractAddress: null,
      sourceFile,
      label: args.label,
      discoveredVulnerabilities: [],
      hypothesisEvaluations: [],
      features: {},
      riskScore: 0,
      confidence: 0,
      parseSuccess: false,
      parseError: parseCheck.error,
      error: `Parse error: ${parseCheck.error}`,
    };
  }

  // Set env vars for pattern injection BEFORE running the analyzer pipeline.
  // The pre-fix stage (in evolution_orchestrator.py) sets VULN_PATTERN_LIBRARY
  // and VULN_TARGET_LABEL so the FeatureExtractor.injectPatternHints() can
  // load and apply known detection patterns without a Claude Code fix loop.
  if (args.label) {
    process.env.VULN_TARGET_LABEL = args.label;
  }
  if (process.env.VULN_PATTERN_LIBRARY) {
    log.debug(`Pattern library injected: ${process.env.VULN_PATTERN_LIBRARY}, label=${args.label || 'none'}`);
  }

  // Step 2: Run full zero-shot analysis pipeline
  try {
    const predictor = await createZeroShotPredictor();

    // The predictor.analyze() does: parse → CFG → taint → features → reasoner → vulnerabilities
    const result = await predictor.analyze(
      sourceCode,
      contractName,
      sourceFile
    );

    // Extract minimal features for the output
    let features: any = {};
    try {
      const fullFeatures = FeatureExtractor.extract(sourceCode, {
        contractName,
        contractAddress: null,
        sourceFile,
      });
      features = {
        vulnerabilityPatterns: fullFeatures.vulnerabilityPatterns,
        injectedPatterns: fullFeatures.injectedPatterns,
        structural: {
          numFunctions: fullFeatures.structural.numFunctions,
          numStateVariables: fullFeatures.structural.numStateVariables,
          numExternalFunctions: fullFeatures.structural.numExternalFunctions,
        },
        taintAnalysis: fullFeatures.taintAnalysis,
      };
    } catch (featErr: any) {
      log.warn(`Feature extraction failed: ${featErr?.message || featErr}`);
      // If feature extraction fails, we still have the reasoner results
    }

    const riskScore = result.discoveredVulnerabilities.length > 0
      ? Math.max(...result.discoveredVulnerabilities.map(v => v.riskScore), 0)
      : 0;

    const confidence = result.discoveredVulnerabilities.length > 0
      ? Math.max(...result.discoveredVulnerabilities.map(v => v.confidence), 0)
      : 0;

    return {
      contractName,
      contractAddress: null,
      sourceFile,
      label: args.label,
      discoveredVulnerabilities: result.discoveredVulnerabilities,
      hypothesisEvaluations: result.hypothesisEvaluations || [],
      features,
      riskScore,
      confidence,
      parseSuccess: true,
    };
  } catch (err: any) {
    const errMsg = err?.message || err?.toString?.() || "Unknown analysis error";
    log.error(`Analysis failed for ${contractName}: ${errMsg}`);

    return {
      contractName,
      contractAddress: null,
      sourceFile,
      label: args.label,
      discoveredVulnerabilities: [],
      hypothesisEvaluations: [],
      features: {},
      riskScore: 0,
      confidence: 0,
      parseSuccess: true, // Parse succeeded but analysis failed
      error: errMsg,
    };
  }
}

// ===========================================================================
// Entry Point
// ===========================================================================

async function main() {
  const args = parseArgs(process.argv);

  if (!args.target) {
    const msg = "Missing required --target argument. Usage: tsx src/analyzer/index.ts --target <source.sol> --label <vuln_type> [--json]";
    process.stderr.write(msg + "\n");
    process.exit(2);
  }

  try {
    const output = await analyze(args);

    if (args.json) {
      process.stdout.write(JSON.stringify(output, null, 2) + "\n");
    } else {
      // Human-readable summary to stderr (so stdout stays clean for JSON piping)
      if (output.parseSuccess) {
        process.stderr.write(`[Analyzer] ${output.contractName}\n`);
        process.stderr.write(`  Risk Score: ${output.riskScore.toFixed(2)}\n`);
        process.stderr.write(`  Confidence: ${output.confidence.toFixed(2)}\n`);
        process.stderr.write(`  Vulnerabilities: ${output.discoveredVulnerabilities.length}\n`);
      } else {
        process.stderr.write(`[Analyzer] Parse FAILED for ${output.contractName}\n`);
        process.stderr.write(`  Error: ${output.parseError}\n`);
      }
      // Still output JSON to stdout for the orchestrator
      process.stdout.write(JSON.stringify(output, null, 2) + "\n");
    }
  } catch (err: any) {
    const errMsg = err?.message || err?.toString?.() || "Fatal error";
    process.stderr.write(`[Analyzer] Fatal error: ${errMsg}\n`);
    process.stdout.write(JSON.stringify({
      contractName: args.target,
      error: errMsg,
      parseSuccess: false,
      parseError: errMsg,
      discoveredVulnerabilities: [],
      hypothesisEvaluations: [],
      features: {},
      riskScore: 0,
      confidence: 0,
    }, null, 2) + "\n");
    process.exit(1);
  }
}

main().catch(err => {
  process.stderr.write(`Unhandled error: ${err?.message || err}\n`);
  process.exit(1);
});

export { analyze, parseArgs, AnalyzerArgs, AnalysisOutput };