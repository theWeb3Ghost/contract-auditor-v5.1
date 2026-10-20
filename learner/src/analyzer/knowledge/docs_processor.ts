/**
 * Documentation Processor — Ingests Solidity, EVM, and Blockchain Documentation.
 *
 * This is the foundation of the zero-shot learning system. Instead of hardcoding
 * vulnerability patterns, we extract all semantic knowledge from authoritative sources:
 *
 * - Solidity documentation (semantics, gotchas, security considerations)
 * - EVM documentation (opcode semantics, gas costs, storage layout)
 * - Blockchain concepts (consensus, state, transactions, gas)
 * - Solidity language constructs (control flow, data types, function calls)
 *
 * The processor builds a KnowledgeGraph of:
 * - Security-relevant facts (e.g., "msg.sender can be manipulated by reentrancy")
 * - Invariant patterns (e.g., "state changes after external calls are unsafe")
 * - Semantic constraints (e.g., "uint256 can overflow in Solidity <0.8")
 * - Attack vectors (e.g., "tx.origin can be manipulated in phishing attacks")
 *
 * Knowledge is represented as triples: (Subject, Relation, Object)
 * and is used by the zero-shot reasoner to discover novel vulnerability patterns.
 */

import { Logger } from '../../lib/logger.js';

const log = new Logger('docs-processor');

// ===========================================================================
// Knowledge Representation
// ===========================================================================

export type KnowledgeRelation =
  | 'CAN_BE_MANIPULATED_BY'
  | 'HAS_INVARIANT'
  | 'LEADS_TO'
  | 'DEPENDS_ON'
  | 'IS_CONTROLLED_BY'
  | 'CAUSES'
  | 'ENABLES'
  | 'RISKS'
  | 'CONSTRAINT'
  | 'OPCODE_SEMANTICS'
  | 'GAS_COST'
  | 'STORAGE_LAYOUT'
  | 'CALL_GRAPH'
  | 'STATE_MUTATION'
  | 'TNT_SOURCE'    // Trust boundary: non-tamperable
  | 'TRUST_SOURCE'  // Trust boundary: potentially tamperable
  | 'ATTACK_VECTOR'
  | 'EXPLOIT_PATTERN'
  | 'DEFENSE_MECHANISM'
  | 'SEMANTIC_RULE'
  | 'LANGUAGE_GOTCHA';

export interface KnowledgeFact {
  id: string;
  subject: string;          // e.g., "msg.sender", "external_call", "SSTORE"
  relation: KnowledgeRelation;
  object: string;           // e.g., "can_be_manipulated_by_reentrancy"
  confidence: number;        // 0-1 confidence in this fact
  source: string;            // Document/path where this was found
  context?: string;          // Surrounding text for context
  tags?: string[];           // Additional categorization tags
}

export interface KnowledgeGraph {
  facts: Map<string, KnowledgeFact>;
  bySubject: Map<string, KnowledgeFact[]>;
  byRelation: Map<KnowledgeRelation, KnowledgeFact[]>;
  byObject: Map<string, KnowledgeFact[]>;
}

export class KnowledgeGraphImpl implements KnowledgeGraph {
  facts: Map<string, KnowledgeFact> = new Map();
  bySubject: Map<string, KnowledgeFact[]> = new Map();
  byRelation: Map<KnowledgeRelation, KnowledgeFact[]> = new Map();
  byObject: Map<string, KnowledgeFact[]> = new Map();

  add(fact: KnowledgeFact): void {
    this.facts.set(fact.id, fact);
    this.index(fact, 'subject');
    this.index(fact, 'relation');
    this.index(fact, 'object');
  }

  private index(fact: KnowledgeFact, key: 'subject' | 'relation' | 'object'): void {
    const map = key === 'subject' ? this.bySubject :
                key === 'relation' ? this.byRelation :
                this.byObject;
    const k = String(fact[key]);
    if (!map.has(k)) map.set(k, []);
    map.get(k)!.push(fact);
  }

  getFactsBySubject(subject: string): KnowledgeFact[] {
    return this.bySubject.get(subject) || [];
  }

  getFactsByRelation(relation: KnowledgeRelation): KnowledgeFact[] {
    return this.byRelation.get(relation) || [];
  }

  getFactsByObject(object: string): KnowledgeFact[] {
    return this.byObject.get(object) || [];
  }

  getAllSubjects(): string[] {
    return [...this.bySubject.keys()];
  }

  size(): number {
    return this.facts.size;
  }
}

// ===========================================================================
// Document Sources
// ===========================================================================

export interface DocumentSource {
  name: string;
  type: 'url' | 'file' | 'text';
  path: string;
  contentType: 'markdown' | 'html' | 'text' | 'pdf';
  securityWeight: number;  // 0-1: how security-relevant this doc is
}

export const DEFAULT_DOCUMENT_SOURCES: DocumentSource[] = [
  {
    name: 'solidity-docs',
    type: 'url',
    path: 'https://docs.soliditylang.org/en/latest/',
    contentType: 'html',
    securityWeight: 0.9
  },
  {
    name: 'evm-docs',
    type: 'url',
    path: 'https://www.evm.codes/',
    contentType: 'html',
    securityWeight: 1.0
  },
  {
    name: 'ethereum-yellow-paper',
    type: 'url',
    path: 'https://ethereum.github.io/yellowpaper/paper.pdf',
    contentType: 'pdf',
    securityWeight: 1.0
  },
  {
    name: 'solidity-security-guide',
    type: 'url',
    path: 'https://github.com/ethereum/smart-contract-best-practices',
    contentType: 'html',
    securityWeight: 1.0
  },
  {
    name: 'consensus-specs',
    type: 'url',
    path: 'https://github.com/ethereum/consensus-specs',
    contentType: 'html',
    securityWeight: 0.8
  },
  {
    name: 'eip-repository',
    type: 'url',
    path: 'https://eips.ethereum.org/',
    contentType: 'html',
    securityWeight: 0.9
  }
];

// ===========================================================================
// Documentation Content
// ===========================================================================

export interface ProcessedDocument {
  id: string;
  source: string;
  url: string;
  title: string;
  content: string;           // Cleaned text content
  sections: DocumentSection[];
  securityFacts: KnowledgeFact[];
}

export interface DocumentSection {
  heading: string;
  content: string;
  securityRelevance: number;  // 0-1
  facts: KnowledgeFact[];
}

// ===========================================================================
// Document Processor
// ===========================================================================

export class DocumentationProcessor {
  private knowledgeGraph: KnowledgeGraphImpl;
  private documents: Map<string, ProcessedDocument> = new Map();

  constructor(knowledgeGraph: KnowledgeGraphImpl) {
    this.knowledgeGraph = knowledgeGraph;
  }

  /**
   * Process a document and extract security knowledge.
   */
  async processDocument(doc: ProcessedDocument): Promise<KnowledgeFact[]> {
    log.info(`Processing document: ${doc.title}`);

    this.documents.set(doc.id, doc);

    const facts: KnowledgeFact[] = [];
    let factCounter = 0;

    // Process each section
    for (const section of doc.sections) {
      const sectionFacts = this.extractFactsFromSection(
        doc.source,
        section,
        doc.id
      );
      facts.push(...sectionFacts);
    }

    // Extract cross-document facts
    const crossFacts = this.extractCrossDocumentFacts(doc, facts);
    facts.push(...crossFacts);

    // Index all facts in the knowledge graph
    for (const fact of facts) {
      this.knowledgeGraph.add(fact);
    }

    log.info(`  Extracted ${facts.length} knowledge facts from ${doc.title}`);

    return facts;
  }

  /**
   * Extract security-relevant facts from a document section.
   * Uses pattern matching and NLP-like rules to identify:
   * - Security considerations and warnings
   * - Semantic constraints and invariants
   * - Attack vectors and exploit techniques
   * - Defense mechanisms
   */
  private extractFactsFromSection(
    source: string,
    section: DocumentSection,
    docId: string
  ): KnowledgeFact[] {
    const facts: KnowledgeFact[] = [];
    const text = section.content.toLowerCase();

    // Pattern 1: "never" / "should not" / "must not" patterns (constraints)
    const constraintMatches = [
      ...section.content.matchAll(/(?:never|should not|must not|avoid)\s+(.{50,200})/gi)
    ];
    for (const match of constraintMatches) {
      facts.push({
        id: `${docId}_fact_${section.heading}_${facts.length}`,
        subject: this.extractSubject(text),
        relation: 'CONSTRAINT',
        object: match[1].trim().substring(0, 100),
        confidence: section.securityRelevance * 0.9,
        source: `${source}:${section.heading}`,
        context: match[0],
        tags: ['constraint', 'security']
      });
    }

    // Pattern 2: "can be" / "is vulnerable to" patterns (attack vectors)
    const attackMatches = [
      ...section.content.matchAll(/(?:can be (?:manipulated|trick|exploited)|vulnerable to|attacked by|reentrancy)(.{0,150})/gi)
    ];
    for (const match of attackMatches) {
      facts.push({
        id: `${docId}_fact_${section.heading}_${facts.length}`,
        subject: this.extractSubject(text),
        relation: 'ATTACK_VECTOR',
        object: match[0].trim().substring(0, 150),
        confidence: section.securityRelevance * 0.8,
        source: `${source}:${section.heading}`,
        context: match[0],
        tags: ['attack', 'exploit']
      });
    }

    // Pattern 3: "external call" / "state mut" patterns (invariants)
    const invariantMatches = [
      ...section.content.matchAll(/(?:external call|state mutat|balance|msg\.sender|tx\.origin)(.{0,100})/gi)
    ];
    for (const match of invariantMatches) {
      facts.push({
        id: `${docId}_fact_${section.heading}_${facts.length}`,
        subject: match[1].trim().substring(0, 50),
        relation: 'HAS_INVARIANT',
        object: this.extractInvariant(match[0]),
        confidence: section.securityRelevance * 0.7,
        source: `${source}:${section.heading}`,
        context: match[0],
        tags: ['invariant', 'state']
      });
    }

    // Pattern 4: EVM opcode references
    const opcodeMatches = [
      ...section.content.matchAll(/`?([A-Z]{3,5})`?(?:$|\s|\.)/g)
    ];
    for (const match of opcodeMatches) {
      const opcode = match[1];
      if (this.isKnownOpcode(opcode)) {
        facts.push({
          id: `${docId}_fact_${section.heading}_${facts.length}`,
          subject: opcode,
          relation: 'OPCODE_SEMANTICS',
          object: this.extractOpcodeSemantics(opcode, section.content),
          confidence: section.securityRelevance * 0.9,
          source: `${source}:${section.heading}`,
          context: match[0],
          tags: ['opcode', 'evm']
        });
      }
    }

    return facts;
  }

  /**
   * Extract cross-document facts by correlating information.
   */
  private extractCrossDocumentFacts(
    doc: ProcessedDocument,
    existingFacts: KnowledgeFact[]
  ): KnowledgeFact[] {
    const facts: KnowledgeFact[] = [];

    // Look for contradictions or gaps between documents
    // e.g., if doc says "external calls are safe" but another says "reentrancy is possible"
    for (const fact of existingFacts) {
      if (fact.relation === 'ATTACK_VECTOR') {
        // Check if the attack vector is documented elsewhere as mitigated
        const mitigations = this.knowledgeGraph.getFactsBySubject(fact.subject)
          .filter(f => f.relation === 'DEFENSE_MECHANISM');

        if (mitigations.length === 0) {
          facts.push({
            id: `cross_${fact.id}_no_mitigation`,
            subject: fact.subject,
            relation: 'ATTACK_VECTOR',
            object: `${fact.object} — no mitigation found in documentation`,
            confidence: fact.confidence * 0.5,
            source: `cross-document:${doc.source}`,
            context: fact.context,
            tags: ['unmitigated', 'high_risk']
          });
        }
      }
    }

    return facts;
  }

  private extractSubject(text: string): string {
    const subjects = [
      'msg.sender', 'tx.origin', 'msg.value', 'block.timestamp',
      'external_call', 'state_change', 'storage', 'calldata',
      'mapping', 'uint256', 'address', 'contract'
    ];
    for (const s of subjects) {
      if (text.includes(s)) return s;
    }
    // Extract first noun phrase
    const match = text.match(/(?:the |a |an )?(\w+)/);
    return match ? match[1] : 'unknown';
  }

  private extractInvariant(text: string): string {
    const lower = text.toLowerCase();

    if (lower.includes('external call') && lower.includes('state')) {
      return 'State changes after external calls violate checks-effects-interactions';
    }
    if (lower.includes('reentrancy')) {
      return 'External calls enable reentrancy if state is updated after call';
    }
    if (lower.includes('msg.sender')) {
      return 'msg.sender changes on reentrant call';
    }
    if (lower.includes('overflow')) {
      return 'Uint arithmetic can overflow without SafeMath or Solidity >=0.8';
    }

    return 'Invariant not fully captured — needs manual review';
  }

  private extractOpcodeSemantics(opcode: string, context: string): string {
    // Known EVM opcode semantics
    const semantics: Record<string, string> = {
      CALL: 'External call — reentrancy risk if state is updated after',
      DELEGATECALL: 'Delegatecall — modifies caller storage, dangerous with untrusted targets',
      STATICCALL: 'Static call — read-only, no state changes',
      SSTORE: 'Storage write — expensive, can trigger reentrancy if after external call',
      SLOAD: 'Storage read — can be stale due to reentrancy',
      CALLVALUE: 'msg.value — attacker-controlled',
      CALLER: 'msg.sender — can change during reentrant call',
      ORIGIN: 'tx.origin — can be manipulated via phishing',
      TIMESTAMP: 'block.timestamp — miner-controlled within ~15s window',
      NUMBER: 'block.number — miner-influenced',
      GAS: 'Remaining gas — can be reduced by attacker',
      BALANCE: 'Account balance — can change between call and check',
      SELFDESTRUCT: 'Contract deletion — state is permanently removed'
    };

    const sem = semantics[opcode];
    if (sem) return sem;

    // Fallback: extract from context
    const inContext = context.match(new RegExp(`${opcode}[^.]{0,100}`));
    return inContext ? inContext[0] : `Opcode ${opcode} — semantics not documented`;
  }

  private isKnownOpcode(opcode: string): boolean {
    return ['CALL', 'DELEGATECALL', 'STATICCALL', 'SSTORE', 'SLOAD',
            'CALLVALUE', 'CALLER', 'ORIGIN', 'TIMESTAMP', 'NUMBER',
            'GAS', 'BALANCE', 'SELFDESTRUCT', 'STOP', 'RETURN',
            'REVERT', 'INVALID', 'CREATE', 'CREATE2', 'LOG0', 'LOG1',
            'LOG2', 'LOG3', 'LOG4'].includes(opcode);
  }
}

// ===========================================================================
// Knowledge Ingestion
// ===========================================================================

export async function ingestDocumentation(
  knowledgeGraph: KnowledgeGraphImpl,
  sources: DocumentSource[] = DEFAULT_DOCUMENT_SOURCES,
  outputDir: string = 'data/knowledge'
): Promise<{ processed: number; totalFacts: number; errors: string[] }> {
  const processor = new DocumentationProcessor(knowledgeGraph);
  const errors: string[] = [];
  let totalFacts = 0;
  let processed = 0;

  for (const source of sources) {
    try {
      log.info(`Ingesting doc: ${source.name} from ${source.path}`);

      let content: string;
      let url: string;

      if (source.type === 'url') {
        content = await fetchUrl(source.path);
        url = source.path;
      } else if (source.type === 'file') {
        content = await readFile(source.path, 'utf-8');
        url = source.path;
      } else {
        content = source.path;
        url = 'inline';
      }

      // Parse the document
      const doc = parseDocument(content, source);
      const facts = await processor.processDocument(doc);
      totalFacts += facts.length;
      processed++;

      // Save processed document
      await mkdir(outputDir, { recursive: true });
      await writeFile(
        join(outputDir, `${source.name}.json`),
        JSON.stringify(doc, null, 2)
      );

    } catch (error: any) {
      log.error(`Failed to ingest ${source.name}:`, error.message);
      errors.push(`${source.name}: ${error.message}`);
    }
  }

  // Save the knowledge graph
  await saveKnowledgeGraph(knowledgeGraph, outputDir);

  // Import at the bottom to avoid circular deps
  function readFile(file: string, encoding: string) {
    // This will use the Node.js fs module
    // For now, placeholder
    return Promise.resolve('');
  }

  return { processed, totalFacts, errors };
}

/**
 * Parse raw text content into structured document.
 */
function parseDocument(content: string, source: DocumentSource): ProcessedDocument {
  const cleanText = cleanHtml(content);

  // Split into sections based on markdown headers or HTML headings
  const sections = splitIntoSections(cleanText);

  return {
    id: `doc_${source.name}_${Date.now()}`,
    source: source.name,
    url: source.path,
    title: source.name,
    content: cleanText,
    sections: sections.map(s => ({
      heading: s.heading,
      content: s.content,
      securityRelevance: computeSecurityRelevance(s.heading, s.content),
      facts: []
    })),
    securityFacts: []
  };
}

function cleanHtml(html: string): string {
  // Basic HTML cleanup
  return html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, '\n')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function splitIntoSections(text: string): Array<{ heading: string; content: string }> {
  const sections: Array<{ heading: string; content: string }> = [];

  // Split by markdown headings or HTML headings
  const parts = text.split(/(?:^|\n)(#{1,6}\s+.+)$/gm);

  let currentHeading = 'Introduction';

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i].trim();
    if (!part) continue;

    // Check if this part is a heading
    const headingMatch = part.match(/^(#{1,6})\s+(.+)$/);
    if (headingMatch) {
      currentHeading = headingMatch[2];
    } else if (part.length > 10) {
      // Content after heading
      sections.push({
        heading: currentHeading,
        content: part
      });
    }
  }

  return sections;
}

function computeSecurityRelevance(heading: string, content: string): number {
  const lowerH = heading.toLowerCase();
  const lowerC = content.toLowerCase();

  // Security-related keywords boost relevance
  const securityKeywords = [
    'security', 'attack', 'vulnerability', 'exploit', 'reentrancy',
    'overflow', 'underflow', 'phishing', 'malicious', 'attack',
    'unsafe', 'danger', 'risk', 'warning', 'caution', 'note',
    'must', 'should', 'never', 'avoid', 'invariant', 'constraint'
  ];

  let score = 0.1; // Base relevance

  for (const kw of securityKeywords) {
    if (lowerH.includes(kw)) score += 0.2;
    if (lowerC.includes(kw)) score += 0.05;
  }

  return Math.min(score, 1.0);
}

async function fetchUrl(url: string): Promise<string> {
  const response = await fetch(url, {
    headers: { 'User-Agent': 'SolidityLearner/1.0 (+https://github.com/ghost/learner)' }
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status} fetching ${url}`);
  }

  return response.text();
}

async function saveKnowledgeGraph(graph: KnowledgeGraphImpl, outputDir: string): Promise<void> {
  await mkdir(outputDir, { recursive: true });

  const facts: KnowledgeFact[] = Array.from(graph.facts.values());

  await writeFile(
    join(outputDir, 'knowledge_graph.json'),
    JSON.stringify({
      createdAt: new Date().toISOString(),
      totalFacts: facts.length,
      subjects: graph.getAllSubjects(),
      facts: facts
    }, null, 2)
  );

  log.info(`Saved knowledge graph: ${facts.length} facts, ${graph.getAllSubjects().length} subjects`);
}

// Import statements needed
import { mkdir, writeFile } from 'fs/promises';
import { join } from 'path';
