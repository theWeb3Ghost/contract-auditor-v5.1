/**
 * LLM-Based Pattern Recognition.
 *
 * Expands the 6 hardcoded attacker hypotheses by consulting an LLM
 * (Anthropic Claude) to generate additional attack vectors from the knowledge graph.
 *
 * Flow:
 * 1. On first call, query the LLM with the knowledge graph facts to produce
 *    20+ new attacker hypotheses (each with preconditions, semanticChain, tags).
 * 2. Cache the LLM-generated hypotheses so we don't burn tokens on every run.
 * 3. Merge LLM hypotheses with the base 6 into the reasoner's hypothesis pool.
 */

import { Logger } from '../../lib/logger.js';
import { KnowledgeGraphImpl } from '../knowledge/docs_processor.js';
import { AttackerHypothesis } from './reasoner.js';

const log = new Logger('llm-patterns');

const LLM_CACHE_PATH = 'data/knowledge/llm_hypotheses.json';

/**
 * Lightweight Anthropic-compatible client.
 * Reads ANTHROPIC_BASE_URL / ANTHROPIC_AUTH_TOKEN / ANTHROPIC_MODEL from .env
 */
class LLMClient {
  private baseUrl: string;
  private token: string;
  private model: string;

  constructor() {
    this.baseUrl = process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com';
    this.token = process.env.ANTHROPIC_AUTH_TOKEN || '';
    this.model = process.env.ANTHROPIC_MODEL || 'claude-3-5-sonnet-20241022';
  }

  async chat(prompt: string, maxTokens: number = 4000): Promise<string> {
    if (!this.token) {
      log.warn('No ANTHROPIC_AUTH_TOKEN set — LLM pattern recognition disabled');
      return '';
    }

    const body = {
      model: this.model,
      max_tokens: maxTokens,
      messages: [{ role: 'user', content: prompt }]
    };

    try {
      const res = await fetch(`${this.baseUrl}/v1/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.token,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify(body)
      });

      if (!res.ok) {
        const text = await res.text();
        log.error(`LLM API error ${res.status}: ${text}`);
        return '';
      }

      const data: any = await res.json();
      // Anthropic API: response.content[0].text
      // Pollinations-style API: response.choices[0].message.content
      let output = '';
      if (data.content && Array.isArray(data.content)) {
        output = data.content[0]?.text || '';
      } else if (data.choices && data.choices[0]?.message?.content) {
        output = data.choices[0].message.content;
      } else if (data.choices && data.choices[0]?.text) {
        output = data.choices[0].text;
      }
      return output;
    } catch (err: any) {
      log.error(`LLM request failed: ${err.message}`);
      return '';
    }
  }
}

/**
 * Use the LLM to generate additional attacker hypotheses from the knowledge graph.
 *
 * The prompt asks the model to imagine it is an auditor reviewing the documented
 * facts and to propose new vulnerability hypotheses that aren't covered by the
 * base 6. Each hypothesis follows the AttackerHypothesis interface.
 */
export async function generateLLMHypotheses(
  kg: KnowledgeGraphImpl,
  count: number = 20
): Promise<AttackerHypothesis[]> {
  // Check cache first
  const cached = await loadCachedHypotheses();
  if (cached && cached.length >= count) {
    log.info(`Using ${cached.length} LLM-generated hypotheses from cache`);
    return cached;
  }

  // Collect a digest of knowledge graph facts to feed to the LLM
  const factsDigest = buildFactsDigest(kg);

  const prompt = `You are a world-class smart-contract security auditor.

Given the following knowledge-graph facts about Solidity and the EVM, propose ${count} novel attacker hypotheses that extend beyond the standard patterns (reentrancy, arithmetic, access-control, timestamp, gas-limit, oracle).

Each hypothesis must be valid JSON inside a JSON array. Format exactly as:

[
  {
    "id": "llm_hyp_N",
    "name": "Human-readable name",
    "description": "How the attack works in 1-2 sentences.",
    "attackGoal": "steal_funds|bypass_auth|service_denied|exfiltrate_data|corrupt_state",
    "preconditions": ["list", "of", "preconditions"],
    "semanticChain": ["step1", "step2", "step3"],
    "confidence": 0.5,
    "source": "llm://claude/opsec-reasoning",
    "novel": true,
    "tags": ["tag1", "tag2"],
    "knowledgeEvidence": []
  }
]

Knowledge graph facts:
${factsDigest}

Focus on concrete, auditable preconditions derived from the facts above.`;

  log.info('Requesting LLM hypotheses from Claude...');
  const client = new LLMClient();
  const raw = await client.chat(prompt, 8000);

  if (!raw) {
    log.warn('LLM returned no hypotheses — falling back to base 6 only');
    return [];
  }

  // Extract JSON array from response (strip any preamble)
  const jsonStart = raw.indexOf('[');
  const jsonEnd = raw.lastIndexOf(']');
  if (jsonStart < 0 || jsonEnd < 0) {
    log.warn('No JSON array found in LLM response');
    return [];
  }

  let parsed: any[];
  try {
    parsed = JSON.parse(raw.slice(jsonStart, jsonEnd + 1));
  } catch (err: any) {
    log.error(`Failed to parse LLM response: ${err.message}`);
    return [];
  }

  const hypotheses: AttackerHypothesis[] = parsed
    .filter(h => h.id && h.name && h.description && h.attackGoal &&
               Array.isArray(h.preconditions) && Array.isArray(h.semanticChain))
    .map(h => ({
      id: h.id,
      name: h.name,
      description: h.description,
      attackGoal: h.attackGoal,
      preconditions: h.preconditions,
      semanticChain: h.semanticChain,
      confidence: h.confidence || 0.5,
      source: h.source || 'llm://claude/opsec-reasoning',
      novel: true,
      tags: h.tags || [],
      knowledgeEvidence: h.knowledgeEvidence || []
    }));

  log.info(`LLM generated ${hypotheses.length} hypotheses`);

  // Cache them
  await saveCachedHypotheses(hypotheses);

  return hypotheses;
}

/**
 * Build a human-readable digest of the knowledge graph facts for the LLM prompt.
 */
function buildFactsDigest(kg: KnowledgeGraphImpl): string {
  const facts = Array.from(kg.facts.values());
  // Sample a subset to fit context — prefer ATTACK_VECTOR and CONSTRAINT relations
  const priority = facts.filter(f =>
    f.relation === 'ATTACK_VECTOR' ||
    f.relation === 'CONSTRAINT' ||
    f.relation === 'LANGUAGE_GOTCHA' ||
    f.relation === 'SEMANTIC_RULE'
  );

  const sample = priority.length >= 80
    ? priority.slice(0, 80)
    : facts.slice(0, Math.min(facts.length, 80));

  const lines = sample.map(f =>
    `- [${f.relation}] ${f.subject} → ${f.object} (confidence: ${f.confidence}) [${f.source}]`
  );

  return lines.join('\n');
}

// ===========================================================================
// Caching helpers
// ===========================================================================

async function loadCachedHypotheses(): Promise<AttackerHypothesis[] | null> {
  const fs = await import('fs/promises');
  try {
    const data = JSON.parse(await fs.readFile(LLM_CACHE_PATH, 'utf-8'));
    if (data.hypotheses && data.hypotheses.length > 0) {
      log.info(`Loaded ${data.hypotheses.length} cached LLM hypotheses`);
      return data.hypotheses as AttackerHypothesis[];
    }
  } catch {
    // File doesn't exist yet
  }
  return null;
}

async function saveCachedHypotheses(hypotheses: AttackerHypothesis[]): Promise<void> {
  const fs = await import('fs/promises');
  const path = await import('path');
  await fs.mkdir(path.dirname(LLM_CACHE_PATH), { recursive: true });
  await fs.writeFile(LLM_CACHE_PATH, JSON.stringify({
    generatedAt: new Date().toISOString(),
    count: hypotheses.length,
    hypotheses
  }, null, 2));
  log.info(`Cached ${hypotheses.length} LLM hypotheses to ${LLM_CACHE_PATH}`);
}
