/**
 * Etherscan v2 API client for fetching verified contract source code.
 *
 * Usage:
 *   const client = new EtherscanClient(process.env.ETHERSCAN_API_KEY);
 *   const source = await client.getSourceCode('0x6b175474e89094c44da98b954eedeac495271d0f');
 *
 * Etherscan v2 uses a single endpoint: https://api.etherscan.io/v2/api?chainid=<CHAIN_ID>
 * This works across 60+ EVM chains (Ethereum, BSC, Polygon, Arbitrum, etc.)
 *
 * Chain IDs:
 *   1  -> Ethereum mainnet
 *   56 -> BSC mainnet
 *   137 -> Polygon (Matic) mainnet
 *   42161 -> Arbitrum One
 *   11155111 -> Sepolia
 *   17000 -> Holesky
 */

import { Logger } from './logger.js';

const log = new Logger('etherscan');

export interface EtherscanSource {
  /** Contract address */
  address: string;
  /** Contract name */
  contractName: string;
  /** Compiler version used (e.g., "v0.8.20+commit.xxx") */
  compilerVersion: string;
  /** Optimization flag */
  optimizationUsed: boolean;
  /** Source code — may be single file or JSON with multiple files */
  sourceCode: string;
  /** ABI if available */
  abi?: string;
  /** Proxy flag */
  isProxy: boolean;
  /** Implementation address for proxies */
  implementation?: string;
}

/**
 * Chain ID constants for Etherscan v2 API.
 */
export const CHAIN_IDS = {
  ETHEREUM: 1,
  GOERLI: 5,
  SEPOLIA: 11155111,
  HOLESKY: 17000,
  BSC: 56,
  BSC_TESTNET: 97,
  POLYGON: 137,
  ARBITRUM: 42161,
  ARBITRUM_NOVA: 42170,
  OPTIMISM: 10,
  FANTOM: 250,
  AVALANCHE: 43114,
  METIS: 1088,
  BOB: 81,
  BASE: 8453,
  LINEA: 59144,
  CELO: 422240,
  MOONBEAM: 1284,
  KAVA: 11111,
} as const;

/** Map network name to chain ID for Etherscan v2 API. */
const NETWORK_TO_CHAIN_ID: Record<string, number> = {
  'mainnet': CHAIN_IDS.ETHEREUM,
  'goerli': CHAIN_IDS.GOERLI,
  'sepolia': CHAIN_IDS.SEPOLIA,
  'holesky': CHAIN_IDS.HOLESKY,
  'polygon': CHAIN_IDS.POLYGON,
  'arbitrum': CHAIN_IDS.ARBITRUM,
  'bsc': CHAIN_IDS.BSC,
  'bsc_testnet': CHAIN_IDS.BSC_TESTNET,
  'optimism': CHAIN_IDS.OPTIMISM,
  'fantom': CHAIN_IDS.FANTOM,
  'avalanche': CHAIN_IDS.AVALANCHE,
  'metis': CHAIN_IDS.METIS,
  'bob': CHAIN_IDS.BOB,
  'base': CHAIN_IDS.BASE,
  'linea': CHAIN_IDS.LINEA,
  'celo': CHAIN_IDS.CELO,
  'moonbeam': CHAIN_IDS.MOONBEAM,
  'kava': CHAIN_IDS.KAVA,
};

/** Map chain ID back to human-readable network name. */
const CHAIN_ID_TO_NETWORK: Record<number, string> = Object.fromEntries(
  Object.entries(NETWORK_TO_CHAIN_ID).map(([name, id]) => [id, name])
);

/** Extract Ethereum contract addresses from Solidity source code. */
export function extractAddresses(sourceCode: string): string[] {
  const addressRegex = /0x[0-9a-fA-F]{40}/g;
  const matches = sourceCode.match(addressRegex) || [];
  return Array.from(new Set(matches.map(a => a.toLowerCase())));
}

export class EtherscanClient {
  private apiKey: string;
  private chainId: number;
  private baseUrl: string;

  /**
   * Create an Etherscan v2 client for a specific chain.
   * All chains use the same endpoint — just different chainid.
   */
  constructor(apiKey: string, network: string = 'mainnet') {
    this.apiKey = apiKey;
    this.chainId = NETWORK_TO_CHAIN_ID[network] || CHAIN_IDS.ETHEREUM;
    // Etherscan v2: single endpoint for ALL EVM chains
    this.baseUrl = 'https://api.etherscan.io/v2/api';
  }

  /**
   * Detect the blockchain network from Foundry/Forge test code.
   * Looks for vm.createSelectFork("rpc_url", blockNumber) calls.
   * Returns the detected network name, or 'mainnet' as fallback.
   */
  static detectNetwork(sourceCode: string): 'mainnet' | 'goerli' | 'sepolia' | 'polygon' | 'arbitrum' | 'bsc' | 'bsc_testnet' | 'holesky' | 'optimism' | 'fantom' | 'avalanche' | 'metis' | 'bob' | 'base' | 'linea' | 'celo' | 'moonbeam' | 'kava' {
    const forkMatch = sourceCode.match(/vm\.createSelectFork\(["']([^"']+)["']/);
    if (forkMatch) {
      const rpc = forkMatch[1].toLowerCase();
      if (rpc.includes('bsc') || rpc.includes('binance')) return 'bsc';
      if (rpc.includes('polygon') || rpc.includes('matic')) return 'polygon';
      if (rpc.includes('arbitrum') || rpc.includes('arb')) return 'arbitrum';
      if (rpc.includes('optimism') || rpc.includes('opt')) return 'optimism';
      if (rpc.includes('fantom') || rpc.includes('ftm')) return 'fantom';
      if (rpc.includes('avalanche') || rpc.includes('avax') || rpc.includes('c-chain')) return 'avalanche';
      if (rpc.includes('metis')) return 'metis';
      if (rpc.includes('bob')) return 'bob';
      if (rpc.includes('base')) return 'base';
      if (rpc.includes('linea')) return 'linea';
      if (rpc.includes('goerli')) return 'goerli';
      if (rpc.includes('sepolia')) return 'sepolia';
      if (rpc.includes('holesky')) return 'holesky';
    }

    // Check for chain ID numbers in fork calls
    const chainIdMatch = sourceCode.match(/vm\.createSelectFork\((\d+)/);
    if (chainIdMatch) {
      const chainId = parseInt(chainIdMatch[1]);
      for (const [network, id] of Object.entries(NETWORK_TO_CHAIN_ID)) {
        if (id === chainId) return network as any;
      }
    }

    if (/createSelectFork.*bsc/i.test(sourceCode)) return 'bsc';
    if (/createSelectFork.*polygon/i.test(sourceCode)) return 'polygon';

    return 'mainnet';
  }

  /**
   * Create an EtherscanClient with auto-detected network.
   * The network is inferred from the test code's vm.createSelectFork calls.
   */
  static createWithDetectedNetwork(apiKey: string, sourceCode: string): EtherscanClient {
    const network = EtherscanClient.detectNetwork(sourceCode);
    return new EtherscanClient(apiKey, network);
  }

  /**
   * Get the chain ID for a network name.
   */
  static getChainId(network: string): number {
    return NETWORK_TO_CHAIN_ID[network] || CHAIN_IDS.ETHEREUM;
  }

  /**
   * Get network name from chain ID.
   */
  static getNetworkFromChainId(chainId: number): string {
    return CHAIN_ID_TO_NETWORK[chainId] || 'mainnet';
  }

  /**
   * Fetch verified source code for a single contract address.
   * Uses Etherscan v2 API: single endpoint with chainid parameter.
   */
  async getSourceCode(address: string): Promise<EtherscanSource | null> {
    const url = `${this.baseUrl}?chainid=${this.chainId}&module=contract&action=getsourcecode&address=${address}&apikey=${this.apiKey}`;

    try {
      const response = await fetch(url, {
        headers: { 'Accept': 'application/json' },
      });

      // Check content type — Etherscan v2 may return HTML redirects
      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        // Try reading as text to see what we got
        const text = (await response.text()).substring(0, 200);
        log.warn(`Non-JSON response for ${address} on chainid=${this.chainId}: ${text}`);
        return null;
      }

      const data = await response.json() as any;

      if (data.status !== '1' || !data.result || data.result.length === 0) {
        log.warn(`No verified source for ${address} on chainid=${this.chainId}: ${data.message || data.result}`);
        return null;
      }

      const result = data.result[0];
      const source = {
        address,
        contractName: result.ContractName || 'unknown',
        compilerVersion: result.CompilerVersion || '',
        optimizationUsed: result.Optimization === 'true',
        sourceCode: result.SourceCode || '',
        abi: result.ABI,
        isProxy: result.Proxy === '1',
        implementation: result.Implementation || undefined,
      };

      log.info(`Fetched source for ${address} (${source.contractName}) on chainid=${this.chainId}`);
      return source;
    } catch (err: any) {
      log.error(`Failed to fetch source for ${address} on chainid=${this.chainId}: ${err.message}`);
      return null;
    }
  }

  /**
   * Extract the Solidity source code from Etherscan's response.
   * Etherscan may return:
   * - A plain string (single file contract)
   * - A JSON string with "sources" key (multi-file contract)
   * - A JSON string wrapped in {{ and }} (double-braced, multi-file)
   */
  extractSourceFromResponse(sourceCode: string): string {
    if (!sourceCode || sourceCode === '') return '';

    // Handle double-brace format {{ ... }}
    // Etherscan wraps JSON source in an extra layer of braces: {{ ... }}
    // We need to strip one { from the start and one } from the end to get valid JSON.
    let jsonStr = sourceCode.trim();
    if (jsonStr.startsWith('{{') && jsonStr.trimEnd().endsWith('}}')) {
      jsonStr = jsonStr.slice(1, -1); // Remove outer { and }
    }

    // Handle JSON-wrapped source
    if (jsonStr.startsWith('{')) {
      try {
        const parsed = JSON.parse(jsonStr);
        // Etherscan multi-file format: {"sources": {filename: {content: "..."}}}
        // or flat format: {filename: {content: "...", ...}}
        if (parsed.sources) {
          return this._combineSources(parsed.sources);
        }
        // Flat format: top-level keys are filenames, values have .content or .source
        if (!parsed.sources && typeof parsed === 'object') {
          const entries = Object.entries(parsed);
          if (entries.length > 0 && entries[0][1] && typeof entries[0][1] === 'object' &&
              ('content' in entries[0][1] || 'source' in entries[0][1])) {
            // Convert flat format to sources-like structure
            const sources: Record<string, any> = {};
            for (const [name, info] of entries) {
              sources[name] = info;
            }
            return this._combineSources(sources);
          }
        }
      } catch {
        // Not valid JSON, return as-is
      }
    }

    // Plain source code
    return sourceCode;
  }

  private _combineSources(sources: Record<string, any>): string {
    const files = Object.entries(sources);
    return files
      .map(([name, info]: [string, any]) => {
        const content = info.content || info.source || '';
        if (content) {
          return `// From: ${name}\n${content}`;
        }
        return '';
      })
      .filter(s => s)
      .join('\n\n');
  }

  /**
   * Fetch source code for multiple addresses with rate limiting.
   */
  async batchGetSource(addresses: string[], batchSize = 5, delayMs = 250): Promise<Record<string, string>> {
    const results: Record<string, string> = {};

    for (let i = 0; i < addresses.length; i += batchSize) {
      const batch = addresses.slice(i, i + batchSize);
      const promises = batch.map(async (addr) => {
        const source = await this.getSourceCode(addr);
        if (source) {
          results[addr] = this.extractSourceFromResponse(source.sourceCode);
        }
      });
      await Promise.all(promises);

      if (i + batchSize < addresses.length) {
        await new Promise(r => setTimeout(r, delayMs));
      }
    }

    return results;
  }
}
