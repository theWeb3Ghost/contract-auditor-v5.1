/**
 * Solidity AST Parser.
 *
 * Parses a token stream from the tokenizer into a structured AST.
 * Implements recursive-descent parsing for the Solidity subset needed
 * for security analysis.
 *
 * Supported constructs:
 * - Pragma directives
 * - Import directives
 * - Using-for declarations
 * - Contract / Interface / Library definitions
 * - Inheritance with base contracts
 * - Structs, Enums, Errors
 * - Function definitions (including constructor, fallback, receive)
 * - Modifiers
 * - State variables (with visibility, mutability)
 * - Function modifiers and override specifiers
 * - All statement types (if/else, for, while, do-while, switch, try/catch)
 * - All expression types (assignments, binary ops, function calls, member access, etc.)
 */

import { tokenize, Token, TokenType, TokenizerError } from './tokenizer.js';
import {
  ASTNode,
  ASTSourceUnit,
  ASTContractDefinition,
  ASTFunctionDefinition,
  ASTParameterList,
  ASTModifierInvocation,
  ASTVariableDeclaration,
  ASTExpressionStatement,
  ASTIfStatement,
  ASTForStatement,
  ASTWhileStatement,
  ASTDoWhileStatement,
  ASTSwitchStatement,
  ASTSwitchCase,
  ASTBlock,
  ASTReturn,
  ASTRevertStatement,
  ASTBreak,
  ASTContinue,
  ASTThrow,
  ASTEmitStatement,
  ASTTryCatch,
  ASTCatchBlock,
  ASTPragmaDirective,
  ASTImportDirective,
  ASTUsingForDeclaration,
  ASTStructDefinition,
  ASTEnumDefinition,
  ASTEnumValue,
  ASTModifierDefinition,
  ASTBaseContract,
  ASTAssignment,
  ASTBinaryOperation,
  ASTFunctionCall,
  ASTIdentifier,
  ASTLiteral,
  ASTMemberAccess,
  ASTIndexAccess,
  ASTTupleExpression,
  ASTUnaryOperation,
  ASTConditional,
  ASTNewExpression,
  ASTDelete,
  ASTElementaryTypeNameExpression,
  ASTExpression,
  ASTTypeName,
  ASTElementaryTypeName,
  ASTUserDefinedTypeName,
  ASTMapping,
  ASTArrayTypeName,
  ASTFunctionTypeName,
  SolidityType,
  ASTSymbolAlias,
} from './types.js';

// ===========================================================================
// Parser Error
// ===========================================================================

export class ParserError extends Error {
  public line: number;
  public col: number;
  public offset: number;

  constructor(message: string, token: Token) {
    super(`${message} at ${token.line}:${token.col}`);
    this.name = 'ParserError';
    this.line = token.line;
    this.col = token.col;
    this.offset = token.offset;
  }
}

// ===========================================================================
// Parser
// ===========================================================================

export class SolidityParser {
  private tokens: Token[];
  private pos: number = 0;
  private scopeCounter: number = 0;
  private sourcePath: string;
  private currentContractName: string = '';

  // Guard against pathological recursion in parseExpression/parseTernary/parsePrimary
  // which can be triggered by malformed Solidity (e.g., deeply nested tuples,
  // self-referential macro-like constructs in preprocessor output, or $-prefixed
  // identifiers that confuse the tokenizer). Without this cap, a malicious or
  // badly-formed contract can cause unbounded recursion → stack overflow →
  // "Invalid array length" when the JS engine's array allocation fails.
  private recursionDepth: number = 0;
  private static readonly MAX_RECURSION_DEPTH = 500;

  // Step budget: prevents pathological parse loops by capping total parser steps
  // at a reasonable multiple of token count. Healthy contracts use < 64 steps/token.
  private stepCount: number = 0;
  private static MAX_STEPS_PER_TOKEN = 32;

  // Watchdog: detect stalls (no progress for many ops) or advancing past EOF
  private stall = 0;
  private lastPos = -1;
  private eofAdv = 0;

  // Diagnostics: records parse failures for member-level isolation
  private diagnostics: { pos: number; msg: string }[] = [];

  constructor(source: string, sourcePath: string = 'source.sol') {
    this.sourcePath = sourcePath;
    try {
      this.tokens = tokenize(source);
    } catch (e: any) {
      // If the tokenizer throws, fall back to a minimal token stream
      // so the parser can still produce a (partial) AST with diagnostics.
      this.tokens = [{ type: TokenType.EOF, value: '', offset: 0, line: 1, col: 1 }];
      this.diagnostics.push({ pos: 0, msg: e instanceof Error ? e.message : String(e) });
    }
  }

  /**
   * Return any parse diagnostics recorded during parsing (member-level failures).
   * Call after parse() to check if any members were skipped due to errors.
   */
  getDiagnostics(): { pos: number; msg: string }[] {
    return this.diagnostics;
  }

  // --- Token utilities ---

  private peek(offset: number = 0): Token {
    if (this.pos === this.lastPos) {
      if (++this.stall > 1_000_000) this.die('no progress for 1M operations');
    } else {
      this.lastPos = this.pos;
      this.stall = 0;
    }
    const idx = this.pos + offset;
    if (idx >= this.tokens.length) {
      return this.tokens[this.tokens.length - 1]; // EOF
    }
    return this.tokens[idx];
  }

  private get current(): Token {
    return this.peek(0);
  }

  private get next(): Token {
    return this.peek(1);
  }

  private advance(): Token {
    const tok = this.current;
    if (tok.type === TokenType.EOF && ++this.eofAdv > 100) {
      this.die('advancing past EOF');
    }
    this.pos++;
    this.tick();
    return tok;
  }

  private match(type: TokenType): boolean {
    return this.current.type === type;
  }

  private check(types: TokenType[]): boolean {
    return types.includes(this.current.type);
  }

  private expect(type: TokenType, errorMsg: string): Token {
    if (!this.match(type)) {
      throw new ParserError(
        `${errorMsg} (expected ${TokenType[type]}, got ${TokenType[this.current.type]})`,
        this.current
      );
    }
    return this.advance();
  }

  /**
   * Like expect(), but if we've hit EOF (truncated source code), recover
   * gracefully instead of throwing. This allows parsing to continue on
   * partially-available source where the end of the file is cut off.
   */
  private expectOrEof(type: TokenType, errorMsg: string): Token | null {
    if (this.match(type)) {
      return this.advance();
    }
    if (this.isAtEnd()) {
      return null; // Graceful recovery on truncated source
    }
    // Also return null if we've hit a closing brace — this signals the end
    // of a block and the statement is implicitly terminated.
    if (this.match(TokenType.RBrace)) {
      return null;
    }
    throw new ParserError(
      `${errorMsg} (expected ${TokenType[type]}, got ${TokenType[this.current.type]})`,
      this.current
    );
  }

  private expectOneOf(types: TokenType[], errorMsg: string): Token {
    if (!this.check(types)) {
      throw new ParserError(
        `${errorMsg} (expected one of [${types.map(t => TokenType[t]).join(', ')}], got ${TokenType[this.current.type]})`,
        this.current
      );
    }
    return this.advance();
  }

  /**
   * Like expect(TokenType.Identifier), but also accepts contextual keywords
   * (error, global, alias, apply, receive, fallback, byte, real) that may be
   * tokenized as keyword types rather than Identifier.
   */
  private expectIdentifier(errorMsg: string): Token {
    if (this.isIdentLike()) {
      return this.advance();
    }
    throw new ParserError(
      `${errorMsg} (expected Identifier, got ${TokenType[this.current.type]})`,
      this.current
    );
  }

  private isAtEnd(): boolean {
    return this.current.type === TokenType.EOF;
  }

  private newScope(): number {
    this.scopeCounter++;
    return this.scopeCounter;
  }

  // --- Keyword helpers ---

  private isKeyword(tokType: TokenType): boolean {
    return tokType >= TokenType.KeywordAbstract && tokType <= TokenType.KeywordVirtual;
  }

  private isVisibilityKeyword(tokType: TokenType): boolean {
    return [
      TokenType.KeywordPublic,
      TokenType.KeywordInternal,
      TokenType.KeywordPrivate,
      TokenType.KeywordExternal
    ].includes(tokType);
  }

  private parseVisibility(): string | null {
    if (this.isVisibilityKeyword(this.current.type)) {
      const vis = this.current.value as string;
      this.advance();
      return vis;
    }
    return null;
  }

  private parseStateMutability(): string | null {
    if (this.match(TokenType.KeywordPayable)) {
      this.advance();
      return 'payable';
    }
    if (this.match(TokenType.KeywordView)) {
      this.advance();
      return 'view';
    }
    if (this.match(TokenType.KeywordPure)) {
      this.advance();
      return 'pure';
    }
    return null;
  }

  // ===========================================================================
  // Entry point
  // ===========================================================================

  /**
   * Parse Solidity source code into an AST.
   */
  static parse(source: string, sourcePath: string = 'source.sol'): ASTSourceUnit {
    const parser = new SolidityParser(source, sourcePath);
    // Don't advance — parseSourceUnit starts at pos=0 (first token)
    return parser.parseSourceUnit();
  }

  static parseTokens(tokens: Token[], sourcePath: string = 'source.sol'): ASTSourceUnit {
    const parser = new SolidityParser('', sourcePath);
    parser.tokens = tokens;
    parser.pos = 0;
    parser.advance();
    return parser.parseSourceUnit();
  }

  private parseSourceUnit(): ASTSourceUnit {
    const children: ASTNode[] = [];
    this.diagnostics = [];

    while (!this.isAtEnd()) {
      const startPos = this.pos;
      try {
        if (this.match(TokenType.KeywordPragma)) {
          this.advance();
          children.push(this.parsePragmaDirective());
        } else if (this.match(TokenType.KeywordImport) || this.match(TokenType.KeywordAlias)) {
          this.advance();
          children.push(this.parseImportDirective());
        } else if (this.match(TokenType.KeywordUsing)) {
          this.advance();
          children.push(this.parseUsingForDeclaration());
        // contract-like definitions
        } else if (this.match(TokenType.KeywordContract) ||
                   this.match(TokenType.KeywordInterface) ||
                   this.match(TokenType.KeywordLibrary) ||
                   this.match(TokenType.KeywordAbstract)) {
          children.push(this.parseContractDefinition());
        // File-level functions, constants, structs, enums, errors
        } else if (this.match(TokenType.KeywordFunction) ||
                   (this.isIdentLike() && this.current.value === 'function')) {
          children.push(this.parseFunctionDefinition());
        } else if (this.match(TokenType.KeywordError)) {
          children.push(this.parseErrorDefinition());
        } else if (this.match(TokenType.KeywordStruct)) {
          children.push(this.parseStructDefinition());
        } else if (this.match(TokenType.KeywordEnum)) {
          children.push(this.parseEnumDefinition());
        } else if (this.isIdentLike() && (this.current.value === 'error' || this.current.value === 'struct' ||
                                          this.current.value === 'enum')) {
          // Contextual keywords tokenized as Identifier — backtrack and parse
          this.pos = startPos;
          try {
            if (this.current.value === 'error') {
              children.push(this.parseErrorDefinition());
            } else if (this.current.value === 'struct') {
              children.push(this.parseStructDefinition());
            } else {
              children.push(this.parseEnumDefinition());
            }
          } catch {
            this.pos = startPos;
            this.skipMember();
          }
        } else if (this.match(TokenType.Identifier) || this.isIdentLike()) {
          // Top-level function, constant, or variable
          try {
            const member = this.parseVariableDeclaration();
            if (member) children.push(member);
          } catch {
            this.pos = startPos;
            this.skipMember();
          }
        } else if (this.checkTypeKind()) {
          // Type keyword (uint, address, etc.) followed by identifier — file-level constant
          try {
            const member = this.parseVariableDeclaration();
            if (member) children.push(member);
          } catch {
            this.pos = startPos;
            this.skipMember();
          }
        } else {
          // Unexpected token at top level — skip to recover
          this.advance();
        }
      } catch (e: any) {
        // Isolate failure: record diagnostic, skip to next member boundary, continue
        this.diagnostics.push({ pos: startPos, msg: e instanceof Error ? e.message : String(e) });
        this.pos = startPos;
        this.skipMember();
      }
    }

    return {
      type: 'SourceUnit',
      nodeType: 'SourceUnit',
      children,
      sourcePaths: [this.sourcePath]
    };
  }

  private parsePragmaDirective(): ASTPragmaDirective {
    // After "pragma", expect identifier (e.g., "solidity") then expression list
    const name = this.expectIdentifier('Expected pragma name').value;

    // Collect all tokens until semicolon as the value
    let valueParts: string[] = [];
    while (!this.isAtEnd() && !this.match(TokenType.Semicolon) && !this.isAtEnd()) {
      valueParts.push(this.current.value);
      this.advance();
    }
    this.expect(TokenType.Semicolon, 'Expected ; after pragma');

    return {
      type: 'PragmaDirective',
      nodeType: 'PragmaDirective',
      name,
      value: valueParts.join(' ')
    };
  }

  private parseImportDirective(): ASTImportDirective {
    // import "path"; or import {a as b, c} from "path"; or import * as name from "path";
    const symbolAliases: ASTSymbolAlias[] = [];
    let path = '';

    if (this.match(TokenType.LBrace)) {
      // import {a as b, c} from "path";
      this.advance(); // consume {
      while (!this.match(TokenType.RBrace)) {
        const from = this.expectIdentifier('Expected import alias').value;
        let to = from;
        if (this.match(TokenType.KeywordAs) ||
            (this.peek().type === TokenType.Identifier && this.peek().value === 'as')) {
          this.advance();
          to = this.expectIdentifier('Expected alias name').value;
        }
        symbolAliases.push({ from, to });
        if (this.match(TokenType.Comma)) {
          this.advance();
        }
      }
      this.advance(); // consume }

      // Expect "from" then path
      if (this.match(TokenType.Identifier) && this.current.value === 'from') {
        this.advance();
      }
      path = this.expect(TokenType.StringLiteral, 'Expected import path').value.replace(/^["']|["']$/g, '');
    } else {
      // import "path"; or import "path" as Name; or import * as Name from "path";
      const firstToken = this.current;
      if (this.match(TokenType.StringLiteral)) {
        this.advance(); // consume the string literal
        path = firstToken.value.replace(/^["']|["']$/g, '');
        // Handle import "path" as Name;
        if (this.match(TokenType.KeywordAs) ||
            (this.peek().type === TokenType.Identifier && this.peek().value === 'as')) {
          this.advance();
          const alias = this.expectIdentifier('Expected alias name after as').value;
          symbolAliases.push({ from: '*', to: alias });
        }
      } else if (this.match(TokenType.Star)) {
        this.advance(); // *
        if (this.match(TokenType.KeywordAs) ||
            (this.peek().type === TokenType.Identifier && this.peek().value === 'as')) {
          this.advance();
        }
        const name = this.expectIdentifier('Expected as name').value;
        symbolAliases.push({ from: '*', to: name });
        if (this.match(TokenType.Identifier) && this.current.value === 'from') {
          this.advance();
        }
        path = this.expect(TokenType.StringLiteral, 'Expected import path').value.replace(/^["']|["']$/g, '');
      } else {
        path = firstToken.value;
      }
    }

    this.expect(TokenType.Semicolon, 'Expected ; after import');

    return {
      type: 'ImportDirective',
      nodeType: 'ImportDirective',
      symbolAliases,
      path
    };
  }

  private parseUsingForDeclaration(): ASTUsingForDeclaration {
    // Supported syntaxes:
    //   using Library for TypeName;
    //   using Library for *;
    //   using {func1 as alias1, func2} for TypeName;
    //   using {func1 as alias1, func2} for uint256 global;
    //   using {func1 as alias1, func2} for * global;
    // Dotted names in braces: using {Lib.func as alias, func2} for uint256;

    let functions: string[] = [];
    let isGlobal = false;

    // Check for braced function list: using {func1 as alias1, func2} for ...
    if (this.match(TokenType.LBrace)) {
      this.advance(); // consume {

      // Parse function list inside braces: func1 as alias1, func2, ...
      while (!this.match(TokenType.RBrace) && !this.isAtEnd()) {
        // Function name can be dotted: LibraryName.functionName
        // Also accept operator tokens (Solidity 0.8.19+ user-defined operators)
        if (this.isIdentLike()) {
          let funcName = this.advance().value;
          // Check for dotted names: .funcName or .LibraryName.funcName
          while (this.match(TokenType.Dot)) {
            this.advance(); // consume dot
            if (!this.isIdentLike()) {
              this.advance();
              continue;
            }
            const part = this.advance().value;
            funcName += `.${part}`;
          }

          // Check for "as alias" syntax — alias can be identifier or operator token
          if (this.match(TokenType.KeywordAs) ||
              (this.peek().type === TokenType.Identifier && this.peek().value === 'as')) {
            this.advance(); // consume 'as'
            if (this.isIdentLike()) {
              const alias = this.advance().value;
              functions.push(`${funcName} as ${alias}`);
            } else {
              // Operator alias (e.g., + or - or * etc.)
              const alias = this.advance().value || 'unknown';
              functions.push(`${funcName} as ${alias}`);
            }
          } else {
            functions.push(funcName);
          }
        } else {
          // Not an identifier — skip token to avoid infinite loop
          this.advance();
        }

        // Comma separator between functions (but not after the last one before })
        if (this.match(TokenType.Comma)) {
          this.advance();
        }
      }
      this.expect(TokenType.RBrace, 'Expected } to close using-for function list');
    } else {
      // Simple form: using Library for TypeName;
      const libName = this.expectIdentifier('Expected library name').value;
      functions.push(libName);
    }

    // Expect "for" keyword
    if (this.match(TokenType.KeywordFor)) {
      this.advance(); // for

      let typeName: ASTTypeName | null = null;
      if (this.match(TokenType.Star)) {
        this.advance(); // for *
        typeName = null;
      } else {
        typeName = this.parseTypeName();
      }

      // Check for "global" keyword (Solidity 0.8.13+)
      if (this.match(TokenType.KeywordGlobal)) {
        this.advance(); // consume 'global'
        isGlobal = true;
      }

      void typeName;
    }

    this.expect(TokenType.Semicolon, 'Expected ; after using-for');

    return {
      type: 'UsingForDeclaration',
      nodeType: 'UsingForDeclaration',
      typeName: null,
      functions,
      isGlobal
    };
  }

  private parseContractDefinition(): ASTContractDefinition {
    let kind: 'contract' | 'interface' | 'library' | 'abstract' = 'contract';
    let isAbstract = false;

    if (this.match(TokenType.KeywordAbstract)) {
      isAbstract = true;
      this.advance();
    }

    if (this.match(TokenType.KeywordContract)) {
      kind = 'contract';
      this.advance();
    } else if (this.match(TokenType.KeywordInterface)) {
      kind = 'interface';
      this.advance();
    } else if (this.match(TokenType.KeywordLibrary)) {
      kind = 'library';
      this.advance();
    } else if (this.match(TokenType.KeywordAbstract)) {
      kind = 'contract';
      this.advance();
    }

    const name = this.expectIdentifier('Expected contract name').value;
    this.currentContractName = name;
    const scope = this.newScope();

    const baseContracts: ASTBaseContract[] = [];

    // Parse inheritance: is Base1, Base2(constructorArgs)
    if (this.match(TokenType.KeywordIs)) {
      this.advance();
      do {
        const basePath = this.parseExpression();
        const baseArgs: ASTExpression[] = [];
        if (this.match(TokenType.LParen)) {
          this.advance();
          while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
            baseArgs.push(this.parseExpression());
            if (this.match(TokenType.Comma)) {
              this.advance();
            }
          }
          this.expect(TokenType.RParen, 'Expected ) after base constructor arguments');
        }
        baseContracts.push({ basePath, arguments: baseArgs });
      } while (this.match(TokenType.Comma) && (this.advance(), true));
    }

    const subNodes: ASTNode[] = [];

    this.expect(TokenType.LBrace, 'Expected { after contract definition');

    while (!this.match(TokenType.RBrace) && !this.isAtEnd()) {
      const startPos = this.pos;
      try {
        const child = this.parseContractMember();
        if (child) {
          subNodes.push(child);
        }
      } catch (e: any) {
        // Isolate failure: record diagnostic, skip to next member boundary, continue
        this.diagnostics.push({ pos: startPos, msg: e instanceof Error ? e.message : String(e) });
        this.pos = startPos;
        this.skipMember();
      }
    }
    if (this.match(TokenType.RBrace)) this.advance(); // consume }

    return {
      type: 'ContractDefinition',
      nodeType: 'ContractDefinition',
      scope,
      name,
      baseContracts,
      subNodes,
      kind,
      isFinal: false,
      isShadowing: false,
      contractDependencies: []
    };
  }

  private parseContractMember(): ASTNode | null {
    // Skip modifiers on members (handled in parseVariableDeclaration / parseFunctionDefinition)
    while (!this.isAtEnd()) {
      this.tick();
      if (this.match(TokenType.LBrace)) {
        // Block-level — shouldn't happen at contract level, but recover
        return this.parseBlock();
      }

      if (this.match(TokenType.Semicolon)) {
        // Empty member — skip
        this.advance();
        continue;
      }

      // Modifier
      if (this.match(TokenType.KeywordModifier)) {
        return this.parseModifierDefinition();
      }

      // Struct
      if (this.match(TokenType.KeywordStruct)) {
        return this.parseStructDefinition();
      }

      // Enum
      if (this.match(TokenType.KeywordEnum)) {
        return this.parseEnumDefinition();
      }

      // Error
      if (this.match(TokenType.KeywordError)) {
        return this.parseErrorDefinition();
      }

      // Function / Constructor / Fallback / Receive
      if (this.match(TokenType.KeywordFunction) ||
          this.match(TokenType.KeywordConstructor) ||
          this.match(TokenType.KeywordFallback) ||
          this.match(TokenType.KeywordReceive)) {
        try {
          return this.parseFunctionDefinition();
        } catch (err: any) {
          // Recovery: skip to the next function or semicolon boundary
          this.recoverToSemicolonOrLBrace();
          continue;
        }
      }

      // Event
      if (this.match(TokenType.KeywordEvent)) {
        try {
          return this.parseEventDefinition();
        } catch (err: any) {
          // Recovery: skip to next semicolon
          this.recoverToSemicolon();
          continue;
        }
      }

      // User-defined value type: type Token is bytes32;
      // (Solidity 0.8.8+) — 'type' is tokenized as KeywordApply
      if (this.match(TokenType.KeywordApply) && this.current.value === 'type') {
        this.advance(); // consume 'type'
        // Parse: Identifier KeywordIs TypeName ;
        this.expectIdentifier('Expected type name after "type"');
        this.advance(); // consume type name
        // 'is' is a keyword (KeywordIs)
        if (this.match(TokenType.KeywordIs)) {
          this.advance(); // consume 'is'
        }
        // Parse the base type (could be primitive or custom), or skip to ;
        if (!this.isAtEnd() && !this.match(TokenType.Semicolon)) {
          this.parseTypeName();
        }
        this.expectOrEof(TokenType.Semicolon, 'Expected ; after type definition');
        continue; // Skip returning a node — user-defined types are not security-relevant
      }

      // State variable
      if (this.match(TokenType.Identifier) || this.isTypeNameStart()) {
        try {
          return this.parseVariableDeclaration();
        } catch (err: any) {
          // Recovery: skip to next semicolon — state var declarations end with ;
          this.recoverToSemicolon();
          continue;
        }
      }

      // Using-for
      if (this.match(TokenType.KeywordUsing)) {
        this.advance();
        return this.parseUsingForDeclaration();
      }

      // Couldn't parse — if we've hit a closing brace, return null so the
      // caller's loop can detect the end of the contract body.
      if (this.match(TokenType.RBrace)) {
        return null;
      }
      // Skip token
      this.advance();
    }
    // Reached EOF without finding a closing brace — return null to let caller handle it
    return null;
  }

  /**
   * Recovery helper: skip tokens until we reach a semicolon or opening brace.
   * Used when parsing fails mid-statement to resynchronize the parser.
   */
  private recoverToSemicolon(): void {
    const MAX_SKIP = 1000;
    let count = 0;
    while (!this.match(TokenType.Semicolon) && !this.isAtEnd() && count < MAX_SKIP) {
      this.advance();
      count++;
    }
    if (this.match(TokenType.Semicolon)) this.advance();
  }

  /**
   * Recovery helper: skip tokens until we reach a semicolon or opening brace.
   */
  private recoverToSemicolonOrLBrace(): void {
    const MAX_SKIP = 1000;
    let count = 0;
    while (!this.match(TokenType.Semicolon) && !this.match(TokenType.LBrace) && !this.isAtEnd() && count < MAX_SKIP) {
      this.advance();
      count++;
    }
    if (this.match(TokenType.Semicolon)) this.advance();
  }

  /**
   * Check if the current token can serve as an identifier in Solidity.
   * Contextual keywords (error, global, alias, apply, receive, fallback, etc.)
   * are accepted as identifiers wherever a name is expected.
   */
  private isIdentLike(): boolean {
    const t = this.current.type;
    return t === TokenType.Identifier ||
           t === TokenType.KeywordError ||
           t === TokenType.KeywordGlobal ||
           t === TokenType.KeywordAlias ||
           t === TokenType.KeywordApply ||
           t === TokenType.KeywordReceive ||
           t === TokenType.KeywordFallback ||
           t === TokenType.KeywordByte ||
           t === TokenType.KeywordReal;
  }

  /**
   * Skip tokens to the boundary of a top-level member: to ';' at depth 0,
   * or past the '}' matching the first '{'. Used for error isolation
   * so one failed member doesn't corrupt the rest of the file.
   */
  private skipMember(): void {
    let depth = 0;
    let count = 0;
    const MAX_SKIP = 10000;
    while (!this.isAtEnd() && count < MAX_SKIP) {
      const t = this.advance().type;
      count++;
      if (t === TokenType.LBrace) depth++;
      else if (t === TokenType.RBrace) {
        if (depth === 0) { return; } // closing brace of the member — caller will handle
        depth--;
      }
      else if (t === TokenType.Semicolon && depth === 0) return;
    }
  }

  private parseModifierDefinition(): ASTModifierDefinition {
    this.advance(); // consume 'modifier'
    const name = this.expectIdentifier('Expected modifier name').value;
    const scope = this.newScope();

    const parameters: ASTParameterList = {
      type: 'ParameterList',
      nodeType: 'ParameterList',
      parameters: []
    };

    // Parameters in parentheses (modifier can take params)
    if (this.match(TokenType.LParen)) {
      this.advance();
      parameters.parameters = this.parseParameterListBody();
      this.expect(TokenType.RParen, 'Expected ) after modifier parameters');
    }

    let body: ASTBlock | null = null;
    if (this.match(TokenType.LBrace)) {
      body = this.parseBlock();
    } else {
      // Modifier with just `_` placeholder
      if (this.match(TokenType.Identifier) && this.current.value === '_') {
        this.advance();
      }
      if (this.match(TokenType.LBrace)) {
        body = this.parseBlock();
      }
    }

    const isVirtual = false; // Would need to check for 'virtual' keyword

    return {
      type: 'ModifierDefinition',
      nodeType: 'ModifierDefinition',
      scope,
      name,
      parameters,
      body,
      isVirtual
    };
  }

  private parseStructDefinition(): ASTStructDefinition {
    this.advance(); // consume 'struct'
    const name = this.expectIdentifier('Expected struct name').value;
    const scope = this.newScope();

    const members: ASTVariableDeclaration[] = [];

    this.expect(TokenType.LBrace, 'Expected { after struct name');

    while (!this.match(TokenType.RBrace) && !this.isAtEnd()) {
      // Struct members are variable declarations without visibility
      const member = this.parseVariableDeclaration(false, false);
      if (member) {
        members.push(member);
      }
      this.expect(TokenType.Semicolon, 'Expected ; after struct member');
    }

    this.advance(); // consume }

    return {
      type: 'StructDefinition',
      nodeType: 'StructDefinition',
      scope,
      name,
      members,
      kind: 'struct',
      linearizable: true
    };
  }

  private parseEnumDefinition(): ASTEnumDefinition {
    this.advance(); // consume 'enum'
    const name = this.expectIdentifier('Expected enum name').value;

    this.expect(TokenType.LBrace, 'Expected { after enum name');

    const members: ASTEnumValue[] = [];
    let value = 0;

    while (!this.match(TokenType.RBrace) && !this.isAtEnd()) {
      const memberName = this.expectIdentifier('Expected enum value name').value;
      members.push({
        type: 'EnumValue',
        nodeType: 'EnumValue',
        name: memberName,
        value: value++
      });

      if (this.match(TokenType.Comma)) {
        this.advance();
      }
    }

    this.advance(); // consume }

    return {
      type: 'EnumDefinition',
      nodeType: 'EnumDefinition',
      name,
      members,
      linearization: []
    };
  }

  private parseErrorDefinition(): ASTStructDefinition {
    // Error definitions look like structs: error MyError(string reason, uint256 amount);
    this.advance(); // consume 'error'
    const name = this.expectIdentifier('Expected error name').value;
    const scope = this.newScope();
    const members: ASTVariableDeclaration[] = [];

    this.expect(TokenType.LParen, 'Expected ( after error name');
    if (!this.match(TokenType.RParen)) {
      while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
        const member = this.parseVariableDeclaration(false, false);
        if (member) {
          members.push(member);
        }
        if (this.match(TokenType.Comma)) {
          this.advance();
        }
      }
    }
    this.expect(TokenType.RParen, 'Expected ) after error parameters');
    this.expect(TokenType.Semicolon, 'Expected ; after error definition');

    return {
      type: 'StructDefinition',
      nodeType: 'StructDefinition',
      scope,
      name,
      members,
      kind: 'error',
      linearizable: true
    };
  }

  private parseEventDefinition(): ASTNode {
    // Events are not part of our AST types but we parse and skip
    this.advance(); // consume 'event'
    this.expectIdentifier('Expected event name');

    if (this.match(TokenType.LParen)) {
      this.advance();
      while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
        const posBefore = this.pos;
        this.parseTypeName();
        if (this.match(TokenType.Identifier)) {
          // indexed keyword or parameter name
          if (this.current.value === 'indexed') {
            this.advance();
          }
          this.expectIdentifier('Expected parameter name');
        }
        // If no progress was made, advance to avoid infinite loop
        if (this.pos === posBefore) {
          this.advance();
        }
        if (this.match(TokenType.Comma)) {
          this.advance();
        }
      }
      this.expect(TokenType.RParen, 'Expected ) after event parameters');
    } else {
      // Anonymous event
    }

    // Use expectOrEof for event semicolons — some test contracts have
    // events without semicolons in interfaces or malformed event defs.
    this.expectOrEof(TokenType.Semicolon, 'Expected ; after event definition');

    // Return a minimal event-like node
    return {
      type: 'StructDefinition',
      nodeType: 'StructDefinition',
      scope: this.newScope(),
      name: '',
      members: [],
      kind: 'enum',
      linearizable: false
    } as ASTStructDefinition;
  }

  private parseFunctionDefinition(): ASTFunctionDefinition {
    let name: string | null = null;
    let functionKind: 'constructor' | 'function' | 'fallback' | 'receive' | 'freeFunction' = 'function';

    if (this.match(TokenType.KeywordConstructor)) {
      this.advance();
      functionKind = 'constructor';
      name = 'constructor';
    } else if (this.match(TokenType.KeywordFunction) ||
               (this.peek().type === TokenType.Identifier && this.peek().value === 'function')) {
      this.advance();
      // Handle anonymous functions: function() external returns(...)
      // The token after 'function' may be '(' (no name) or an Identifier (has name)
      if (this.match(TokenType.LParen)) {
        name = '';  // anonymous function — could be fallback (pre-0.6) or free function
        functionKind = 'fallback';
      } else {
        name = this.expectIdentifier('Expected function name').value;
        // Legacy constructor detection: function ContractName() before 0.4.22
        // where a function with the same name as the enclosing contract is a constructor
        if (name === this.currentContractName) {
          functionKind = 'constructor';
        } else {
          functionKind = 'function';
        }
      }
    } else if (this.match(TokenType.KeywordFallback) ||
               (this.peek().type === TokenType.Identifier && this.peek().value === 'fallback')) {
      this.advance();
      functionKind = 'fallback';
      name = 'fallback';
    } else if (this.match(TokenType.KeywordReceive) ||
               (this.peek().type === TokenType.Identifier && this.peek().value === 'receive')) {
      this.advance();
      functionKind = 'receive';
      name = 'receive';
    } else if (this.isIdentLike()) {
      // Function name might be a contextual keyword (e.g. 'error', 'receive')
      this.advance();
      name = this.current.value;
      functionKind = 'function';
    } else {
      this.advance();
    }

    const scope = this.newScope();

    // Parameters
    const parameters: ASTParameterList = {
      type: 'ParameterList',
      nodeType: 'ParameterList',
      parameters: []
    };

    this.expect(TokenType.LParen, 'Expected ( after function name');
    parameters.parameters = this.parseParameterListBody();
    this.expectOrEof(TokenType.RParen, 'Expected ) after parameters');

    // Return parameters
    let returnParameters: ASTParameterList = {
      type: 'ParameterList', nodeType: 'ParameterList', parameters: []
    };

    // Modifiers and visibility (also handles 'returns' which can appear after modifiers)
    const modifiers: ASTModifierInvocation[] = [];
    let visibility: string = 'public';
    let stateMutability: string = 'nonpayable';
    let isPayable = false;
    let isView = false;
    let isPure = false;
    let overrideList: string[] = [];

    while (true) {
      this.tick();
      if (this.isVisibilityKeyword(this.current.type)) {
        visibility = this.parseVisibility()!;
      } else if (this.match(TokenType.KeywordPayable)) {
        this.parseStateMutability();
        isPayable = true;
        stateMutability = 'payable';
      } else if (this.match(TokenType.KeywordView)) {
        this.parseStateMutability();
        isView = true;
        stateMutability = 'view';
      } else if (this.match(TokenType.KeywordPure)) {
        this.parseStateMutability();
        isPure = true;
        stateMutability = 'pure';
      } else if (this.match(TokenType.KeywordVirtual)) {
        this.advance();
      } else if (this.match(TokenType.KeywordConstant)) {
        // Older Solidity style: function foo() external constant
        this.advance();
      } else if (this.match(TokenType.KeywordImmutable)) {
        // Older Solidity style: function foo() external immutable
        this.advance();
      } else if (this.match(TokenType.KeywordOverride)) {
        this.advance();
        if (this.match(TokenType.LParen)) {
          this.advance();
          while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
            overrideList.push(this.expect(TokenType.Identifier, 'Expected override contract name').value);
            if (this.match(TokenType.Comma)) {
              this.advance();
            }
          }
          this.expectOrEof(TokenType.RParen, 'Expected ) after override list');
        }
      } else if (this.match(TokenType.KeywordReturns)) {
        this.advance();
        this.expect(TokenType.LParen, 'Expected ( after returns');
        returnParameters.parameters = this.parseParameterListBody();
        this.expectOrEof(TokenType.RParen, 'Expected ) after return parameters');
      } else if (this.match(TokenType.Identifier)) {
        // Modifier invocation (e.g., onlyOwner, whenNotPaused, ...)
        const modName = this.current.value;
        this.advance();
        const modArgs: ASTExpression[] = [];
        if (this.match(TokenType.LParen)) {
          this.advance();
          while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
            modArgs.push(this.parseExpression());
            if (this.match(TokenType.Comma)) {
              this.advance();
            }
          }
          this.expectOrEof(TokenType.RParen, 'Expected ) after modifier arguments');
        }
        modifiers.push({ type: 'ModifierInvocation', name: modName, arguments: modArgs });
      } else {
        break;
      }
    }

    // Body
    let body: ASTBlock | null = null;
    if (this.match(TokenType.LBrace)) {
      body = this.parseBlock();
      // After parsing body, skip any stray tokens until EOF or next contract member
    } else {
      // No body — abstract or external function declaration
      // Use expectOrEof for recovery on truncated/malformed source
      this.expectOrEof(TokenType.Semicolon, 'Expected ; or { after function declaration');
    }

    return {
      type: 'FunctionDefinition',
      nodeType: 'FunctionDefinition',
      scope,
      name,
      parameters,
      returnParameters,
      modifiers,
      body,
      functionKind,
      visibility: visibility as 'public' | 'internal' | 'private' | 'external',
      stateMutability: stateMutability as 'nonpayable' | 'payable' | 'view' | 'pure',
      isConstructor: functionKind === 'constructor',
      isPayable,
      isView,
      isPure,
      overrides: overrideList,
      implemented: body !== null
    };
  }

  private parseParameterListBody(): ASTVariableDeclaration[] {
    const params: ASTVariableDeclaration[] = [];

    if (this.match(TokenType.RParen)) {
      return params;
    }

    while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
      const param = this.parseFunctionParameter();
      if (param) {
        params.push(param);
      }
      if (this.match(TokenType.Comma)) {
        this.advance();
      }
    }

    return params;
  }

  private parseFunctionParameter(): ASTVariableDeclaration | null {
    // Parse type name + visibility + optional name
    const typeName = this.parseTypeName();

    if (!typeName) {
      return null;
    }

    // Storage location
    let storageLocation: 'default' | 'storage' | 'memory' | 'calldata' = 'default';
    if (this.match(TokenType.KeywordStorage)) {
      storageLocation = 'storage';
      this.advance();
    } else if (this.match(TokenType.KeywordMemory)) {
      storageLocation = 'memory';
      this.advance();
    } else if (this.match(TokenType.KeywordCalldata)) {
      storageLocation = 'calldata';
      this.advance();
    }

    // Optional name — accept contextual keywords (error, receive, etc.) as identifiers
    let name = '';
    if (this.isIdentLike()) {
      name = this.current.value;
      this.advance();
    }

    // Check for indexed keyword (events)
    if (this.match(TokenType.Identifier) && this.current.value === 'indexed') {
      this.advance();
    }

    return {
      type: 'VariableDeclaration',
      nodeType: 'VariableDeclaration',
      scope: this.scopeCounter,
      declared: 0,
      isStateVar: false,
      isIndexed: false,
      isVisibleInStruct: false,
      isConstant: false,
      isImmutable: false,
      name,
      typeName,
      value: null,
      storageLocation,
      stateVariableVisibility: 'default',
      functionVisibility: 'public',
      slot: null,
      offset: null
    };
  }

  private parseVariableDeclaration(
    withVisibility: boolean = true,
    expectSemicolon: boolean = true
  ): ASTVariableDeclaration | null {
    const typeName = this.parseTypeName();

    if (!typeName) {
      return null;
    }

    const scope = this.newScope();
    const id = scope;

    // Storage location
    let storageLocation: 'default' | 'storage' | 'memory' | 'calldata' = 'default';
    if (withVisibility) {
      if (this.match(TokenType.KeywordStorage)) {
        storageLocation = 'storage';
        this.advance();
      } else if (this.match(TokenType.KeywordMemory)) {
        storageLocation = 'memory';
        this.advance();
      } else if (this.match(TokenType.KeywordCalldata)) {
        storageLocation = 'calldata';
        this.advance();
      }
    }

    // Parse modifiers and variable name in any order
    let stateVariableVisibility: string = 'default';
    let isConstant = false;
    let isImmutable = false;
    let functionVisibility: string = 'public';
    let name = '';

    if (withVisibility) {
      while (
        this.match(TokenType.Identifier) ||
        this.match(TokenType.KeywordConstant) ||
        this.match(TokenType.KeywordImmutable) ||
        this.isVisibilityKeyword(this.current.type)
      ) {
        // Get the keyword/identifier value
        let kw: string | null = null;

        if (this.match(TokenType.KeywordConstant)) {
          kw = 'constant';
        } else if (this.match(TokenType.KeywordImmutable)) {
          kw = 'immutable';
        } else if (this.isVisibilityKeyword(this.current.type)) {
          kw = this.current.value;
        }

        if (kw !== null) {
          // This is a modifier keyword — consume it
          this.advance();
          if (kw === 'constant') {
            isConstant = true;
          } else if (kw === 'immutable') {
            isImmutable = true;
          } else {
            stateVariableVisibility = kw;
            functionVisibility = kw;
          }
        } else if (this.match(TokenType.Identifier)) {
          // This is the variable name
          name = this.current.value;
          this.advance();
        } else {
          // Unknown identifier — treat as name
          break;
        }
      }
    } else {
      // Without visibility, just grab the name
      if (this.match(TokenType.Identifier)) {
        name = this.current.value;
        this.advance();
      }
    }

    // Optional initial value
    let value: ASTExpression | null = null;
    if (this.match(TokenType.Assign)) {
      this.advance();
      value = this.parseExpression();
    }

    if (expectSemicolon) {
      this.expectOrEof(TokenType.Semicolon, 'Expected ; after variable declaration');
    }

    return {
      type: 'VariableDeclaration',
      nodeType: 'VariableDeclaration',
      scope: id,
      declared: id,
      isStateVar: false,
      isIndexed: false,
      isVisibleInStruct: false,
      isConstant,
      isImmutable,
      name,
      typeName,
      value,
      storageLocation,
      stateVariableVisibility: stateVariableVisibility as 'default' | 'public' | 'internal' | 'private',
      functionVisibility: functionVisibility as 'public' | 'internal' | 'private' | 'external',
      slot: null,
      offset: null
    };
  }

  // ===========================================================================
  // Type name parsing
  // ===========================================================================

  private parseTypeName(): ASTTypeName | null {
    if (this.isAtEnd() || this.match(TokenType.Semicolon)) {
      return null;
    }

    // Mapping type
    if (this.match(TokenType.Identifier) && this.current.value === 'mapping') {
      this.advance();
      this.expect(TokenType.LParen, 'Expected ( after mapping');

      const keyType = this.parseTypeName();
      if (!keyType) throw new ParserError('Expected mapping key type', this.current);

      // Optional key name
      let keyName = '';
      if (this.match(TokenType.Identifier)) {
        keyName = this.current.value;
        this.advance();
      }

      this.expect(TokenType.FatArrow, 'Expected => in mapping');

      const valueType = this.parseTypeName();
      if (!valueType) throw new ParserError('Expected mapping value type', this.current);

      // Optional value name
      let valueName = '';
      if (this.match(TokenType.Identifier)) {
        valueName = this.current.value;
        this.advance();
      }

      this.expect(TokenType.RParen, 'Expected ) after mapping value type');

      return {
        type: 'Mapping',
        nodeType: 'Mapping',
        keyType,
        keyName,
        valueType,
        valueName
      };
    }

    // Contract / struct / enum type, or "address" (which comes as Identifier)
    // Also handles dotted names like SwapGuard.Data or TokenTypes.TokenAmount
    if (this.match(TokenType.Identifier)) {
      const name = this.current.value;
      this.advance();

      // Handle dotted names: SwapGuard.Data, TokenTypes.TokenAmount, etc.
      let pathParts = [name];
      while (this.match(TokenType.Dot)) {
        this.advance(); // consume .
        if (this.match(TokenType.Identifier)) {
          pathParts.push(this.current.value);
          this.advance();
        } else {
          break;
        }
      }
      const fullTypeName = pathParts.join('.');

      // address payable — handle when address comes in as Identifier
      if (name === 'address' && this.match(TokenType.KeywordPayable)) {
        pathParts.push('payable');
        this.advance(); // consume 'payable'
      }

      // Array type
      if (this.match(TokenType.LBracket)) {
        this.advance();
        let length: ASTExpression | null = null;
        if (!this.match(TokenType.RBracket)) {
          length = this.parseExpression();
          // Guard against non-standard array dimensions (e.g. uint256[999999999999999])
          // that would cause "Invalid array length" when downstream code tries to
          // allocate an array of that size. We accept any expression here — the
          // guard is downstream, but we cap absurd literal sizes.
          if (length && length.type === 'Literal' && typeof length.value === 'number') {
            if (!Number.isFinite(length.value) || length.value < 0 || length.value > 1e15) {
              throw new ParserError(
                `Array length ${length.value} is outside safe range`,
                this.current
              );
            }
          }
          this.expect(TokenType.RBracket, 'Expected ] after array length');
        }
        // RBracket already consumed by expect() above; nothing to advance here

        let baseType: ASTTypeName;
        if (fullTypeName === 'address payable') {
          baseType = {
            type: 'ElementaryTypeName',
            nodeType: 'ElementaryTypeName',
            name: fullTypeName,
            state: 'address'
          };
        } else {
          baseType = {
            type: 'UserDefinedTypeName',
            nodeType: 'UserDefinedTypeName',
            name: pathParts[0],
            path: pathParts,
            referencedDeclaration: 0
          };
        }

        return {
          type: 'ArrayTypeName',
          nodeType: 'ArrayTypeName',
          baseType: baseType,
          length
        };
      }

      if (fullTypeName === 'address payable') {
        return {
          type: 'ElementaryTypeName',
          nodeType: 'ElementaryTypeName',
          name: fullTypeName,
          state: 'address'
        };
      }

      return {
        type: 'UserDefinedTypeName',
        nodeType: 'UserDefinedTypeName',
        name: pathParts[0],
        path: pathParts,
        referencedDeclaration: 0
      };
    }

    // Elementary types
    if (this.match(TokenType.KeywordString) || this.match(TokenType.KeywordInt) ||
        this.match(TokenType.KeywordUint) || this.match(TokenType.KeywordBool) ||
        this.match(TokenType.KeywordAddress) || this.match(TokenType.KeywordBytes) ||
        this.match(TokenType.KeywordReal) || this.match(TokenType.KeywordByte)) {
      const typeStr = this.current.value;
      this.advance();

      let fullType = typeStr;

      // Sized int/uint/bytes
      if (this.match(TokenType.NumberLiteral)) {
        const sizeValue = this.current.value.toString();
        // Validate that the size is a reasonable integer — non-standard Solidity
        // (e.g. from preprocessor macros, $-prefixed vars, or corrupted tokens)
        // can produce NumberLiteral tokens with garbage values like "1e+21" or
        // extremely long digit strings that later cause "Invalid array length"
        // when used as an array index or size.
        if (!/^\d+$/.test(sizeValue) || parseInt(sizeValue, 10) > 256) {
          throw new ParserError(
            `Invalid type size "${sizeValue}" — expected a valid integer (1-256)`,
            this.current
          );
        }
        fullType += sizeValue;
        this.advance();
      }

      // address payable
      if (typeStr === 'address') {
        if (this.match(TokenType.Identifier) && this.current.value === 'payable') {
          fullType += ' payable';
          this.advance();
        }
      }

      // Array type: uint256[], address payable[], bytes32[], etc.
      if (this.match(TokenType.LBracket)) {
        const baseType: ASTTypeName = {
          type: 'ElementaryTypeName',
          nodeType: 'ElementaryTypeName',
          name: fullType,
          state: fullType.replace(' payable', '')
        };
        this.advance(); // consume [
        let length: ASTExpression | null = null;
        if (!this.match(TokenType.RBracket)) {
          length = this.parseExpression();
          this.expect(TokenType.RBracket, 'Expected ] after array length');
        }
        // RBracket already consumed by expect() above; nothing to advance here
        return {
          type: 'ArrayTypeName',
          nodeType: 'ArrayTypeName',
          baseType: baseType,
          length
        };
      }

      return {
        type: 'ElementaryTypeName',
        nodeType: 'ElementaryTypeName',
        name: fullType,
        state: fullType.replace(' payable', '')
      };
    }

    // Fallback type detection via identifier
    if (this.match(TokenType.Identifier)) {
      const typeStr = this.current.value;
      this.advance();

      // Could be 'address payable'
      if (typeStr === 'address' && this.match(TokenType.Identifier) && this.current.value === 'payable') {
        this.advance();
        return {
          type: 'ElementaryTypeName',
          nodeType: 'ElementaryTypeName',
          name: 'address payable',
          state: 'address'
        };
      }

      // Could be function type
      if (typeStr === 'function') {
        const params = this.parseFunctionTypeParams();
        const retParams = this.parseFunctionReturnType();
        let mutability: string = 'nonpayable';
        if (this.match(TokenType.KeywordPayable)) { mutability = 'payable'; this.advance(); }
        else if (this.match(TokenType.KeywordView)) { mutability = 'view'; this.advance(); }
        else if (this.match(TokenType.KeywordPure)) { mutability = 'pure'; this.advance(); }

        const visibility = this.parseVisibility();
        if (!visibility) {
          throw new ParserError('Expected visibility for function type', this.current);
        }

        return {
          type: 'FunctionTypeName',
          nodeType: 'FunctionTypeName',
          parameterTypes: params,
          returnParameterTypes: retParams,
          visibility: visibility as 'public' | 'internal' | 'private' | 'external',
          stateMutability: mutability as 'nonpayable' | 'payable' | 'view' | 'pure'
        };
      }

      return {
        type: 'UserDefinedTypeName',
        nodeType: 'UserDefinedTypeName',
        name: typeStr,
        path: [typeStr],
        referencedDeclaration: 0
      };
    }

    return null;
  }

  private parseFunctionTypeParams(): ASTParameterList {
    const params: ASTVariableDeclaration[] = [];

    this.expect(TokenType.LParen, 'Expected ( for function type parameters');

    if (!this.match(TokenType.RParen)) {
      while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
        const param = this.parseFunctionParameter();
        if (param) params.push(param);
        if (this.match(TokenType.Comma)) this.advance();
      }
    }
    this.expect(TokenType.RParen, 'Expected ) for function type parameters');

    return { type: 'ParameterList', nodeType: 'ParameterList', parameters: params };
  }

  private parseFunctionReturnType(): ASTParameterList {
    const retParams: ASTVariableDeclaration[] = [];

    if (this.match(TokenType.KeywordReturns)) {
      this.advance();
      this.expect(TokenType.LParen, 'Expected ( after returns');
      if (!this.match(TokenType.RParen)) {
        while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
          const posBefore = this.pos;
          const param = this.parseFunctionParameter();
          if (param) retParams.push(param);
          // If no progress was made, advance to avoid infinite loop on
          // constructs like bare '[' in array type declarations
          if (this.pos === posBefore) {
            this.advance();
          }
          if (this.match(TokenType.Comma)) this.advance();
        }
      }
      this.expect(TokenType.RParen, 'Expected ) after return parameters');
    }

    return { type: 'ParameterList', nodeType: 'ParameterList', parameters: retParams };
  }

  private isTypeNameStart(): boolean {
    const t = this.current.type;
    return [
      TokenType.KeywordString,
      TokenType.KeywordInt,
      TokenType.KeywordUint,
      TokenType.KeywordBool,
      TokenType.KeywordAddress,
      TokenType.KeywordBytes,
      TokenType.KeywordReal,
      TokenType.KeywordByte,
      TokenType.Identifier
    ].includes(t);
  }

  /**
   * Check if the current token is a type keyword or identifier (for file-level
   * constant declarations like `uint256 constant FOO = 1;`).
   */
  private checkTypeKind(): boolean {
    const t = this.current.type;
    return [
      TokenType.KeywordString,
      TokenType.KeywordInt,
      TokenType.KeywordUint,
      TokenType.KeywordBool,
      TokenType.KeywordAddress,
      TokenType.KeywordBytes,
      TokenType.KeywordReal,
      TokenType.KeywordByte,
      TokenType.Identifier
    ].includes(t);
  }

  /**
   * Consume a storage location keyword (memory, storage, calldata) if present.
   * These appear between type names and variable names in function params and tuples.
   */
  private skipStorageLocation(): void {
    if (this.match(TokenType.KeywordMemory) ||
        this.match(TokenType.KeywordStorage) ||
        this.match(TokenType.KeywordCalldata)) {
      this.advance();
    }
  }

  /**
   * Heuristic: check if this position looks like a type declaration
   * (e.g., "uint256 x;", "address owner;", "bool active;")
   * vs an expression (e.g., "balances[msg.sender] += value;")
   *
   * We look at the current identifier and the next token:
   * - If current is a known Solidity type (uint256, address, bool, etc.) and
   *   the next token is an Identifier or =, it's likely a declaration
   * - If current is `var`, it's a declaration
   * - Otherwise (e.g., `balances` followed by `[`), it's an expression
   */
  private looksLikeTypeDeclaration(): boolean {
    if (!this.match(TokenType.Identifier)) return false;

    const currentVal = this.current.value;
    const nextTok = this.next;

    // Known Solidity primitive types
    const primitiveTypes = [
      'uint', 'uint8', 'uint16', 'uint32', 'uint64', 'uint128', 'uint256',
      'int', 'int8', 'int16', 'int32', 'int64', 'int128', 'int256',
      'address', 'bool', 'string', 'bytes', 'bytes1', 'bytes32',
      'real', 'byte', 'function'
    ];

    // Also match patterns like uint256[] or address[]
    if (currentVal === 'var') return true;

    // payable(...) and primitive type followed by ( are type casts, NOT declarations.
    // e.g. "payable(msg.sender).transfer(amount);" or "address(0x1234).call(...)"
    // These should go through the expression statement path, not variable declaration.
    if ((currentVal === 'payable' && nextTok.type === TokenType.LParen) ||
        (primitiveTypes.includes(currentVal) && nextTok.type === TokenType.LParen)) {
      return false;
    }

    if (primitiveTypes.includes(currentVal)) {
      // Next should be an identifier (name) or LParen (function type) or LBracket (array)
      // Note: LParen for type casts is handled above
      // Also handle "address payable" and "address payable[] memory var" patterns
      if (nextTok.type === TokenType.Identifier ||
          nextTok.type === TokenType.LBracket) {
        return true;
      }
      // "bytes memory varName", "uint256 storage varName", etc.
      // Storage location keyword between primitive type and variable name
      if (nextTok.type === TokenType.KeywordMemory ||
          nextTok.type === TokenType.KeywordStorage ||
          nextTok.type === TokenType.KeywordCalldata) {
        const afterStorage = this.peek(2);
        return afterStorage.type === TokenType.Identifier ||
               afterStorage.type === TokenType.LBracket;
      }
      // "address payable" — check what follows payable
      if (nextTok.type === TokenType.KeywordPayable) {
        const afterPayable = this.peek(2);
        if (afterPayable.type === TokenType.KeywordMemory ||
            afterPayable.type === TokenType.KeywordStorage ||
            afterPayable.type === TokenType.KeywordCalldata) {
          const afterStorage = this.peek(3);
          return afterStorage.type === TokenType.Identifier ||
                 afterStorage.type === TokenType.LBracket;
        }
        return afterPayable.type === TokenType.Identifier ||
               afterPayable.type === TokenType.LBracket;
      }
      return false;
    }

    // Could be a contract name as type: "MyContract x" — check if followed by identifier then =/;
    // This is heuristic: if current identifier is followed by another identifier, it could be a type
    if (nextTok.type === TokenType.Identifier) {
      // Could be "MyType variableName" or "balances[msg.sender]"
      // If next-next is Identifier or Assign or Semicolon or LBrace, likely a declaration
      const nextNext = this.peek(2);
      if (nextNext.type === TokenType.Identifier ||
          nextNext.type === TokenType.Assign ||
          nextNext.type === TokenType.Semicolon) {
        return true;
      }
    }

    // User-defined type with storage location: "MetaTransaction memory metaTx = ..."
    // or "MyStruct storage s = ...", "bytes32[] memory arr = ..."
    if (nextTok.type === TokenType.KeywordMemory ||
        nextTok.type === TokenType.KeywordStorage ||
        nextTok.type === TokenType.KeywordCalldata) {
      const afterStorage = this.peek(2);
      if (afterStorage.type === TokenType.Identifier) {
        const afterIdent = this.peek(3);
        // "MyType memory varName = ..." or "MyType memory varName;"
        // or "MyType memory varName, ..." (in parameter lists)
        if (afterIdent.type === TokenType.Assign ||
            afterIdent.type === TokenType.Semicolon ||
            afterIdent.type === TokenType.Comma) {
          return true;
        }
        // Also handle "MyType[] memory varName" — after brackets then memory then name
        // Already handled above via LBracket path
      }
    }

    // Could be a dotted type name: "SwapGuard.Data[]", "TokenTypes.TokenAmount"
    // Scan forward past dotted components and array brackets
    if (nextTok.type === TokenType.Dot) {
      let scanIdx = 1;
      let sawBrackets = false;
      while (scanIdx < 100) {
        const t = this.peek(scanIdx);
        if (t.type === TokenType.Dot) {
          scanIdx++;
          if (this.peek(scanIdx).type === TokenType.Identifier) {
            scanIdx++;
          } else {
            return false;
          }
        } else if (t.type === TokenType.LBracket) {
          // Array brackets after dotted name
          scanIdx++;
          let depth = 1;
          while (depth > 0 && scanIdx < 100) {
            const inner = this.peek(scanIdx);
            if (inner.type === TokenType.LBracket) { depth++; scanIdx++; }
            else if (inner.type === TokenType.RBracket) { depth--; scanIdx++; }
            else { scanIdx++; }
          }
          sawBrackets = true;
        } else if (t.type === TokenType.KeywordMemory ||
                   t.type === TokenType.KeywordStorage ||
                   t.type === TokenType.KeywordCalldata) {
          // Storage location after dotted type: "V3Utils.SwapParams memory params"
          const afterStorage = this.peek(scanIdx + 1);
          if (afterStorage.type === TokenType.Identifier ||
              afterStorage.type === TokenType.Assign ||
              afterStorage.type === TokenType.Semicolon) {
            return true;
          }
          break;
        } else if (t.type === TokenType.Identifier) {
          // After a dotted type name, if we see Identifier then [ or =,
          // it's likely an expression like "set.x[0] = ..." not a declaration
          const afterIdent = this.peek(scanIdx + 1);
          if (afterIdent.type === TokenType.LBracket ||
              afterIdent.type === TokenType.Assign) {
            return false; // Expression, not type declaration
          }
          // Could be "V3Utils.SwapParams memory params" — storage location follows
          if (afterIdent.type === TokenType.KeywordMemory ||
              afterIdent.type === TokenType.KeywordStorage ||
              afterIdent.type === TokenType.KeywordCalldata) {
            const afterStorage = this.peek(scanIdx + 2);
            if (afterStorage.type === TokenType.Identifier ||
                afterStorage.type === TokenType.Assign ||
                afterStorage.type === TokenType.Semicolon) {
              return true;
            }
            break;
          }
          // If we saw brackets before this identifier, it's likely
          // "SomeType[] arrName" — a declaration with array type
          if (sawBrackets) return true;
          // Otherwise, treat as declaration: "MyType varName" or "MyType()"
          return true;
        } else if (t.type === TokenType.Assign) {
          // After brackets, = means it's an expression: "set.x[0] = ..."
          // Without brackets, = means it's a declaration: "MyType x = ..."
          return !sawBrackets;
        } else if (t.type === TokenType.Semicolon) {
          return true;
        } else {
          break;
        }
      }
    }

    // Handle user-defined type arrays: "MyStruct[] varName" or "MyContract[][] varName"
    // The current identifier could be a user-defined type (contract, struct, enum)
    // followed by LBracket indicating an array type. The variable name will appear
    // after the closing RBracket.
    if (nextTok.type === TokenType.LBracket) {
      // Scan forward past all bracket pairs to see what follows
      let scanIdx = 1; // Start at the LBracket (peek(1) = nextTok)
      while (scanIdx < 100) {
        const t = this.peek(scanIdx);
        if (t.type === TokenType.LBracket) {
          // Find matching RBracket — could be [], [expr], or nested [[], []]
          scanIdx++;
          let depth = 1;
          while (depth > 0 && scanIdx < 100) {
            const inner = this.peek(scanIdx);
            if (inner.type === TokenType.LBracket) { depth++; scanIdx++; }
            else if (inner.type === TokenType.RBracket) { depth--; scanIdx++; }
            else { scanIdx++; }
          }
        } else if (t.type === TokenType.RBracket) {
          // Unbalanced — shouldn't happen, but just advance
          scanIdx++;
        } else if (t.type === TokenType.EOF) {
          return false;
        } else {
          // Found something other than brackets — check if it's a valid declaration
          break;
        }
      }
      const afterArray = this.peek(scanIdx);
      // If we see Identifier or Semicolon after brackets, it's likely a declaration:
      // "MyStruct[] varName" or "MyStruct[];" (unlikely but acceptable)
      if (afterArray.type === TokenType.Identifier ||
          afterArray.type === TokenType.Semicolon) {
        return true;
      }
      // Storage location keyword (memory/storage/calldata) between type and name:
      // "MyStruct[] memory varName" — skip past it and check for Identifier
      if (afterArray.type === TokenType.KeywordMemory ||
          afterArray.type === TokenType.KeywordStorage ||
          afterArray.type === TokenType.KeywordCalldata) {
        const afterStorage = this.peek(scanIdx + 1);
        if (afterStorage.type === TokenType.Identifier ||
            afterStorage.type === TokenType.Assign ||
            afterStorage.type === TokenType.Semicolon) {
          return true;
        }
        // "MyStruct[] memory;" is unlikely but possible
        if (afterStorage.type === TokenType.Semicolon) return true;
      }
      // If we see Assign directly after brackets without an intervening Identifier,
      // it's likely an indexed assignment like "arr[0] = expr", NOT a declaration.
      if (afterArray.type === TokenType.Assign) {
        return false;
      }
    }

    return false;
  }

  // ===========================================================================
  // Block and statement parsing
  // ===========================================================================

  private parseBlock(): ASTBlock {
    // If we're already at a closing brace (empty or malformed block), return early
    if (this.match(TokenType.RBrace)) {
      const block: ASTBlock = {
        type: 'Block',
        nodeType: 'Block',
        statements: [],
        tryCallCount: 0,
        tryDelegatecallCount: 0,
        hasStateMutation: false
      };
      return block;
    }
    this.expect(TokenType.LBrace, 'Expected { at block start');

    const block: ASTBlock = {
      type: 'Block',
      nodeType: 'Block',
      statements: [],
      tryCallCount: 0,
      tryDelegatecallCount: 0,
      hasStateMutation: false
    };

    // Guard against infinite loops in malformed contracts where parseStatement
    // returns null without advancing the token position. This can happen with
    // non-standard Solidity constructs (e.g., assembly blocks, $-prefixed vars,
    // preprocessor artifacts) that the parser doesn't recognize.
    let safetyCounter = 0;
    const MAX_STATEMENTS = 50000;
    while (!this.match(TokenType.RBrace) && !this.isAtEnd()) {
      this.tick();
      const posBefore = this.pos;
      const stmt = this.parseStatement();
      if (stmt) {
        block.statements.push(stmt);
      }
      // If the statement parser didn't consume any tokens, advance manually
      // to avoid an infinite loop. But limit total iterations to prevent
      // pathological cases where the contract is just garbage tokens.
      if (this.pos === posBefore) {
        this.advance();
        block.statements.push({
          type: 'ExpressionStatement',
          nodeType: 'ExpressionStatement',
          expression: {
            type: 'Identifier',
            nodeType: 'Identifier',
            name: `_skipped_${this.current.value}`,
            referencedDeclaration: null,
            isTainted: false,
            isConstant: false
          }
        });
      }
      safetyCounter++;
      if (safetyCounter > MAX_STATEMENTS) {
        throw new ParserError(
          `Safety limit exceeded: too many statements in block (>${MAX_STATEMENTS}). `+
          `Possible malformed contract or non-standard Solidity syntax.`,
          this.current
        );
      }
    }

    this.advance(); // consume }
    return block;
  }

  private parseStatement(): ASTNode | null {
    // Inline assembly blocks: assembly { ... }
    // These are skipped to maintain parse continuity — inline assembly
    // contains EVM-level operations that our AST-level analyzer doesn't model.
    // Inline assembly blocks: assembly { ... }
    // These are skipped to maintain parse continuity — inline assembly
    // contains EVM-level operations that our AST-level analyzer doesn't model.
    if (this.match(TokenType.KeywordAssembly) ||
        (this.peek().type === TokenType.Identifier && this.peek().value === 'assembly')) {
      return this.parseAssemblyBlock();
    }

    // unchecked { ... } blocks (Solidity 0.8+) — arithmetic in these blocks
    // can overflow/underflow. Parse the block normally so we can analyze
    // the contained statements for vulnerabilities.
    if (this.peek().type === TokenType.Identifier && this.peek().value === 'unchecked' &&
        this.peek(1).type === TokenType.LBrace) {
      this.advance(); // consume 'unchecked'
      return this.parseBlock();
    }

    // Simple statements
    if (this.match(TokenType.KeywordBreak) ||
        (this.match(TokenType.Identifier) && this.current.value === 'break')) {
      this.advance();
      this.expect(TokenType.Semicolon, 'Expected ; after break');
      return { type: 'Break', nodeType: 'Break' };
    }

    if (this.match(TokenType.KeywordContinue) ||
        (this.match(TokenType.Identifier) && this.current.value === 'continue')) {
      this.advance();
      this.expect(TokenType.Semicolon, 'Expected ; after continue');
      return { type: 'Continue', nodeType: 'Continue' };
    }

    if (this.match(TokenType.KeywordThrow) ||
        (this.match(TokenType.Identifier) && this.current.value === 'throw')) {
      this.advance();
      this.expect(TokenType.Semicolon, 'Expected ; after throw');
      return { type: 'Throw', nodeType: 'Throw' };
    }

    if ((this.match(TokenType.Identifier) && this.current.value === 'if')) {
      return this.parseIfStatement();
    }

    if (this.match(TokenType.KeywordFor) ||
        (this.match(TokenType.Identifier) && this.current.value === 'for')) {
      return this.parseForStatement();
    }

    if (this.match(TokenType.KeywordWhile) ||
        (this.match(TokenType.Identifier) && this.current.value === 'while')) {
      return this.parseWhileStatement();
    }

    if (this.match(TokenType.KeywordDo) ||
        (this.match(TokenType.Identifier) && this.current.value === 'do')) {
      return this.parseDoWhileStatement();
    }

    if ((this.match(TokenType.Identifier) && this.current.value === 'switch')) {
      return this.parseSwitchStatement();
    }

    if (this.match(TokenType.KeywordReturn) ||
        (this.match(TokenType.Identifier) && this.current.value === 'return')) {
      return this.parseReturn();
    }

    if (this.match(TokenType.KeywordRevert) ||
        (this.match(TokenType.Identifier) && this.current.value === 'revert')) {
      return this.parseRevertStatement();
    }

    if (this.match(TokenType.KeywordTry) ||
        (this.match(TokenType.Identifier) && this.current.value === 'try')) {
      return this.parseTryCatch();
    }

    if (this.match(TokenType.KeywordEmit) ||
        (this.match(TokenType.Identifier) && this.current.value === 'emit')) {
      return this.parseEmitStatement();
    }

    if (this.match(TokenType.KeywordDelete) ||
        (this.match(TokenType.Identifier) && this.current.value === 'delete')) {
      this.advance();
      const del: ASTDelete = {
        type: 'Delete',
        nodeType: 'Delete',
        variable: this.parseExpression()
      };
      this.expect(TokenType.Semicolon, 'Expected ; after delete');
      return del;
    }

    // Block
    if (this.match(TokenType.LBrace)) {
      return this.parseBlock();
    }

    // Variable declaration
    // Only treat as declaration if the type is a known Solidity type keyword
    // (uint256, address, bool, etc.) or uses 'var' keyword.
    // This distinguishes "uint256 balance;" (declaration) from
    // "balances[msg.sender] += msg.value;" (expression statement).
    if (this.match(TokenType.KeywordVar) || this.looksLikeTypeDeclaration()) {
      const vd = this.parseVariableDeclaration(true, true);
      return vd;
    }

    // Expression statement (assignment, function call, etc.)
    if (this.match(TokenType.Identifier) || this.match(TokenType.NumberLiteral) ||
        this.match(TokenType.StringLiteral) || this.match(TokenType.LParen) ||
        this.match(TokenType.LBrace) || this.match(TokenType.Plus) ||
        this.match(TokenType.Minus) || this.match(TokenType.Star) ||
        this.match(TokenType.Bang) || this.match(TokenType.Increment) ||
        this.match(TokenType.Decrement) || this.match(TokenType.KeywordNew) ||
        this.match(TokenType.KeywordPayable) ||
        (this.match(TokenType.KeywordApply) && this.current.value === 'type')) {
      const expr = this.parseExpression();
      try {
        this.expectOrEof(TokenType.Semicolon, 'Expected ; after expression');
      } catch (err: any) {
        // Recovery: skip to next semicolon and return what we parsed.
        // This handles cases like "uint256 x = uint(y).memory;" where
        // the expression parse is incomplete, or Foundry test patterns
        // where storage keywords leak into expression context.
        this.recoverToSemicolon();
      }
      return {
        type: 'ExpressionStatement',
        nodeType: 'ExpressionStatement',
        expression: expr
      };
    }

    // If we got here, skip the token
    this.advance();
    return null;
  }

  /**
   * Parse an inline assembly block: assembly [("string" | String)] { ... }
   * Skips the entire assembly block contents since the AST-level analyzer
   * doesn't model EVM opcodes. The block may contain nested braces.
   */
  private parseAssemblyBlock(): ASTNode | null {
    // Consume 'assembly' keyword (already matched by caller)
    if (this.match(TokenType.KeywordAssembly) ||
        (this.match(TokenType.Identifier) && this.current.value === 'assembly')) {
      this.advance();
    }

    // Check for inline assembly string name: assembly "name" {
    if (this.match(TokenType.StringLiteral)) {
      this.advance();
    }

    // Expect opening brace
    if (this.match(TokenType.LBrace)) {
      this.advance(); // consume {
      let depth = 1;
      while (depth > 0 && !this.isAtEnd()) {
        if (this.match(TokenType.LBrace)) {
          this.advance();
          depth++;
        } else if (this.match(TokenType.RBrace)) {
          this.advance();
          depth--;
        } else {
          this.advance();
        }
      }
    }

    return {
      type: 'InlineAssembly' as any,
      nodeType: 'InlineAssembly' as any,
      language: 'assembly',
      source: '',
      expressions: []
    } as ASTNode;
  }

  private parseIfStatement(): ASTIfStatement {
    this.advance(); // consume 'if'
    this.expect(TokenType.LParen, 'Expected ( after if');
    const condition = this.parseExpression();
    this.expect(TokenType.RParen, 'Expected ) after if condition');

    const scope = this.newScope();
    const body = this.parseStatement() || this.parseBlock();

    let elseBody: ASTNode | null = null;
    if (this.match(TokenType.Identifier) && this.current.value === 'else') {
      this.advance(); // consume 'else'
      if (this.match(TokenType.Identifier) && this.current.value === 'if' as string) {
        elseBody = this.parseIfStatement();
      } else {
        elseBody = this.parseStatement() || this.parseBlock();
      }
    }

    // Analyze: is condition based on calldata/tainted input
    const conditionTainted = this.containsTaintedInput(condition);

    return {
      type: 'IfStatement',
      nodeType: 'IfStatement',
      condition,
      body: body as ASTNode,
      elseBody,
      conditionTainted
    };
  }

  private parseForStatement(): ASTForStatement {
    this.advance(); // consume 'for'
    this.expect(TokenType.LParen, 'Expected ( after for');

    let initExpression: ASTExpression | null = null;
    if (!this.match(TokenType.Semicolon)) {
      if (this.looksLikeTypeDeclaration()) {
        initExpression = this.parseVariableDeclaration(true, false) as ASTExpression;
      } else {
        initExpression = this.parseExpression();
      }
    }
    this.expect(TokenType.Semicolon, 'Expected ; after for init');

    let condition: ASTExpression | null = null;
    if (!this.match(TokenType.Semicolon)) {
      condition = this.parseExpression();
    }
    this.expect(TokenType.Semicolon, 'Expected ; after for condition');

    let loopExpression: ASTExpression | null = null;
    if (!this.match(TokenType.RParen)) {
      loopExpression = this.parseExpression();
    }
    this.expect(TokenType.RParen, 'Expected ) after for header');

    const bodyScope = this.newScope();
    const body = this.parseStatement() || this.parseBlock();

    const userControlledBound = condition ? this.containsTaintedInput(condition) : false;

    return {
      type: 'ForStatement',
      nodeType: 'ForStatement',
      condition,
      body: body as ASTNode,
      initExpression,
      loopExpression,
      userControlledBound
    };
  }

  private parseWhileStatement(): ASTWhileStatement {
    this.advance(); // consume 'while'
    this.expect(TokenType.LParen, 'Expected ( after while');
    const condition = this.parseExpression();
    this.expect(TokenType.RParen, 'Expected ) after while condition');

    const body = this.parseStatement() || this.parseBlock();

    return {
      type: 'WhileStatement',
      nodeType: 'WhileStatement',
      condition,
      body: body as ASTNode
    };
  }

  private parseDoWhileStatement(): ASTDoWhileStatement {
    this.advance(); // consume 'do'
    const body = this.parseStatement() || this.parseBlock();
    // 'while' may be tokenized as KeywordWhile or as an Identifier.
    // Accept both to handle different tokenizer implementations.
    if (!this.match(TokenType.KeywordWhile) &&
        !(this.match(TokenType.Identifier) && this.current.value === 'while')) {
      throw new ParserError('Expected while after do', this.current);
    }
    this.advance();
    this.expect(TokenType.LParen, 'Expected ( after while');
    const condition = this.parseExpression();
    this.expect(TokenType.RParen, 'Expected ) after while condition');
    this.expect(TokenType.Semicolon, 'Expected ; after do-while');

    return {
      type: 'DoWhileStatement',
      nodeType: 'DoWhileStatement',
      condition,
      body: body as ASTNode
    };
  }

  private parseSwitchStatement(): ASTSwitchStatement {
    this.advance(); // consume 'switch'
    this.expect(TokenType.LParen, 'Expected ( after switch');
    const expression = this.parseExpression();
    this.expect(TokenType.RParen, 'Expected ) after switch expression');

    this.expect(TokenType.LBrace, 'Expected { after switch expression');

    const cases: ASTSwitchCase[] = [];

    while (!this.match(TokenType.RBrace) && !this.isAtEnd()) {
      if (this.match(TokenType.Identifier) && (this.current.value === 'case' as string)) {
        this.advance();
        const expr = this.parseExpression();
        this.expect(TokenType.Colon, 'Expected : after case value');

        const statements: ASTNode[] = [];
        while (!this.match(TokenType.RBrace) &&
               !this.isAtEnd()) {
          // Check if next token starts a new case/default label
          if (this.match(TokenType.Identifier) &&
              (this.current.value === 'case' || this.current.value === 'default')) {
            break;
          }
          const stmt = this.parseStatement();
          if (stmt) statements.push(stmt as ASTNode);
        }
        cases.push({ type: 'SwitchCase', nodeType: 'SwitchCase', expression: expr, statements });
      } else if (this.match(TokenType.Identifier) && (this.current.value === 'default' as string)) {
        this.advance();
        this.expect(TokenType.Colon, 'Expected : after default');

        const statements: ASTNode[] = [];
        while (!this.match(TokenType.RBrace) &&
               !this.isAtEnd()) {
          if (this.match(TokenType.Identifier) &&
              (this.current.value === 'case' || this.current.value === 'default')) {
            break;
          }
          const stmt = this.parseStatement();
          if (stmt) statements.push(stmt as ASTNode);
        }
        cases.push({ type: 'SwitchCase', nodeType: 'SwitchCase', expression: null, statements });
      } else {
        this.advance(); // skip unknown token
      }
    }

    this.advance(); // consume }

    return {
      type: 'SwitchStatement',
      nodeType: 'SwitchStatement',
      expression,
      cases
    };
  }

  private parseReturn(): ASTReturn {
    this.advance(); // consume 'return'
    let expression: ASTExpression | null = null;
    if (!this.match(TokenType.Semicolon)) {
      expression = this.parseExpression();
    }
    this.expect(TokenType.Semicolon, 'Expected ; after return');

    return {
      type: 'Return',
      nodeType: 'Return',
      expression
    };
  }

  private parseRevertStatement(): ASTRevertStatement {
    this.advance(); // consume 'revert'

    let errorExpr: ASTExpression | null = null;
    const args: ASTExpression[] = [];

    if (this.match(TokenType.LParen)) {
      this.advance();
      if (!this.match(TokenType.RParen)) {
        // Could be revert("message") or revert CustomError(args)
        const first = this.parseExpression();
        args.push(first);
        while (this.match(TokenType.Comma)) {
          this.advance();
          args.push(this.parseExpression());
        }
        errorExpr = args[0];
      }
      this.expect(TokenType.RParen, 'Expected ) after revert arguments');
    }

    this.expect(TokenType.Semicolon, 'Expected ; after revert');

    return {
      type: 'RevertStatement',
      nodeType: 'RevertStatement',
      Expression: errorExpr,
      arguments: args
    };
  }

  private parseEmitStatement(): ASTEmitStatement {
    this.advance(); // consume 'emit'
    const expr = this.parseExpression() as ASTFunctionCall;

    this.expectOrEof(TokenType.Semicolon, 'Expected ; after emit');

    return {
      type: 'EmitStatement',
      nodeType: 'EmitStatement',
      eventCall: expr
    };
  }

  private parseTryCatch(): ASTTryCatch {
    this.advance(); // consume 'try'
    const tryCall = this.parseExpression() as ASTFunctionCall;

    // Return parameters for try
    let returnParameters: ASTParameterList = {
      type: 'ParameterList', nodeType: 'ParameterList', parameters: []
    };

    // Check for 'returns' — may be tokenized as KeywordReturns or Identifier
    if (this.match(TokenType.KeywordReturns) ||
        (this.peek().type === TokenType.Identifier && this.peek().value === 'returns')) {
      this.advance();
      this.expect(TokenType.LParen, 'Expected ( after returns');
      returnParameters.parameters = this.parseParameterListBody();
      this.expect(TokenType.RParen, 'Expected ) after return parameters');
    }

    // parseBlock handles its own { — no expect(LBrace) needed here
    const tryBody = this.parseBlock();

    const catchBlocks: ASTCatchBlock[] = [];

    // Match 'catch' as either KeywordCatch or Identifier
    while (this.match(TokenType.KeywordCatch) ||
           (this.peek().type === TokenType.Identifier && this.peek().value === 'catch')) {
      this.advance(); // consume 'catch'
      this.advance();

      let catchKind: 'default' | 'error' | 'panic' | 'revert' = 'default';
      let args: ASTVariableDeclaration[] = [];

      // catch { } — no args
      // catch (CustomError) { }
      // catch (string memory msg, uint256 code) { }
      // catch (bytes memory lowLevel) { }

      if (this.match(TokenType.LParen)) {
        this.advance();

        if (!this.match(TokenType.RParen)) {
          // Parse first parameter — could be a type (string, bytes, CustomError) or identifier
          const param = this.parseFunctionParameter();
          if (param) args.push(param);

          // Check for additional parameters: catch (string memory, uint256)
          while (this.match(TokenType.Comma)) {
            this.advance();
            const param2 = this.parseFunctionParameter();
            if (param2) {
              args.push(param2);
              // If we have (bytes ..., ...) it's a revert catch
              if (param && param.typeName && typeof param.typeName === 'object' && 'name' in param.typeName &&
                  String((param.typeName as any).name).includes('bytes')) {
                catchKind = 'revert';
              }
              // If we have (string ..., uint256) it's a panic catch
              else if (param && param.typeName && typeof param.typeName === 'object' && 'name' in param.typeName &&
                       String((param.typeName as any).name).includes('string') && param2.typeName &&
                       typeof param2.typeName === 'object' && 'name' in param2.typeName &&
                       String((param2.typeName as any).name).match(/uint/)) {
                catchKind = 'panic';
              }
            }
          }
        }

        this.expect(TokenType.RParen, 'Expected ) after catch parameters');
      }

      // Catch block body
      const catchBody = this.parseBlock();

      catchBlocks.push({
        type: 'CatchBlock',
        nodeType: 'CatchBlock',
        arguments: { type: 'ParameterList', nodeType: 'ParameterList', parameters: args },
        block: catchBody,
        catchKind
      });
    }

    return {
      type: 'TryCatch',
      nodeType: 'TryCatch',
      tryCall,
      returnParameters,
      catchBlocks
    };
  }

  // ===========================================================================
  // Expression parsing
  // ===========================================================================

  /**
   * Parse an expression using Pratt parsing.
   * Handles operator precedence correctly.
   */
  private parseExpression(): ASTExpression {
    this.tick();
    return this.parseTernary();
  }

  private parseTernary(): ASTExpression {
    this.checkRecursionDepth();
    try {
      const cond = this.parseBinary(1);
      if (this.match(TokenType.Question)) {
        this.advance();
        const trueExpr = this.parseTernary();
        this.expect(TokenType.Colon, 'Expected : after ternary true branch');
        const falseExpr = this.parseTernary();
        return {
          type: 'Conditional',
          nodeType: 'Conditional',
          condition: cond,
          trueExpression: trueExpr,
          falseExpression: falseExpr
        };
      }
      return cond;
    } finally {
      this.recursionDepth--;
    }
  }

  /**
   * Check whether we've exceeded the recursion ceiling.
   * Throws a controlled ParserError instead of letting the JS engine
   * hit a stack overflow / "Invalid array length" from unbounded recursion.
   */
  private checkRecursionDepth(): void {
    if (this.recursionDepth >= SolidityParser.MAX_RECURSION_DEPTH) {
      throw new ParserError(
        `Maximum expression nesting depth exceeded (${SolidityParser.MAX_RECURSION_DEPTH}) — ` +
        `likely malformed or adversarial Solidity (deeply nested tuples, macro-like constructs)`,
        this.current
      );
    }
    this.recursionDepth++;
  }

  /**
   * Step budget: cap total parser steps to prevent pathological loops
   * where the parser makes slow but non-zero progress (e.g., advancing one
   * token per iteration in a large file) or exponential backtracking.
   * Healthy contracts use well under 32 steps per token.
   */
  private tick(): void {
    this.stepCount++;
    if (this.stepCount % 10000 === 0) {
      console.error(`tick ${this.stepCount}: pos=${this.pos}/${this.tokens.length}`);
    }
    const maxSteps = this.tokens.length * SolidityParser.MAX_STEPS_PER_TOKEN;
    if (this.stepCount > maxSteps) {
      throw new ParserError(
        `Parse budget exceeded: ${this.stepCount} steps for ${this.tokens.length} tokens ` +
        `(max ${SolidityParser.MAX_STEPS_PER_TOKEN} steps/token) — possible exponential backtracking`,
        this.current
      );
    }
  }

  /**
   * Watchdog: detect stalls (no progress for many ops) or advancing past EOF
   */
  private die(why: string): never {
    const t = this.tokens[Math.min(this.pos, this.tokens.length - 1)];
    const stack = new Error().stack || '';
    throw new Error(`${why} @ ${t.line}:${t.col} ${TokenType[t.type]} '${t.value}'\n${stack.substring(0, 200)}`);
  }

  // Operator precedence (higher binds tighter)
  // 1: || (lowest)
  // 2: &&
  // 3: | ^ &
  // 4: == != < > <= >=
  // 5: << >>
  // 6: + -
  // 7: * / %
  // 8: unary -, !, ++, --
  // 9: ** (Solidity doesn't have this, but for completeness)
  // 10: member access, index, function call (highest)

  private parseBinary(minPrec: number): ASTExpression {
    this.checkRecursionDepth();
    try {
      let left = this.parseUnary(10);

    while (true) {
      this.tick();
      const opToken = this.current;

      // Check for plain assignment (=)
      if (this.match(TokenType.Assign)) {
        this.advance();
        return {
          type: 'Assignment',
          nodeType: 'Assignment',
          operator: '=',
          left,
          right: this.parseTernary()  // assignment has low precedence
        } as ASTAssignment;
      }

      // Check for compound assignment operators (+=, -=, *=, /=, %=, &=, |=, ^=, <<=, >>=)
      const compoundOp = this.getCompoundAssignment(opToken);
      if (compoundOp) {
        this.advance();
        const right = this.parseTernary(); // compound assignment right-hand side at same precedence as plain =
        return {
          type: 'Assignment',
          nodeType: 'Assignment',
          operator: compoundOp,
          // Left side is binary operation: left = left <op without => > right
          left: {
            type: 'BinaryOperation',
            nodeType: 'BinaryOperation',
            operator: compoundOp.replace('=', '') as any,
            left,
            right,
            overflowRisk: 'checked'
          } as ASTExpression,
          right: right // Keep right for simplicity; the BinaryOperation captures the actual semantics
        } as any; // We use a simplified form — the left side already contains the operation
      }

      const prec = this.getBinaryPrecedence(opToken);
      if (prec < minPrec) break;

      // ** is right-associative — parse right side at same precedence, not prec+1
      if (opToken.type === TokenType.StarStar) {
        this.advance();
        left = {
          type: 'BinaryOperation',
          nodeType: 'BinaryOperation',
          operator: '**',
          left,
          right: this.parseBinary(prec), // right-assoc: parse at same precedence
          overflowRisk: 'checked'
        };
        continue;
      }

      this.advance();
      const op = opToken.value;

      left = {
        type: 'BinaryOperation',
        nodeType: 'BinaryOperation',
        operator: op as '==' | '!=' | '<' | '<=' | '>' | '>=' | '+' | '-' | '*' | '/' | '%' | '&&' | '||' | '&' | '|' | '^' | '<<' | '>>',
        left,
        right: this.parseBinary(prec + 1),
        overflowRisk: 'checked' // Will be refined later
      };
    }

    return left;
    } finally {
      this.recursionDepth--;
    }
  }

  private getCompoundAssignment(tok: Token): string | null {
    switch (tok.type) {
      case TokenType.PlusAssign: return '+=';
      case TokenType.MinusAssign: return '-=';
      case TokenType.StarAssign: return '*=';
      case TokenType.SlashAssign: return '/=';
      case TokenType.PercentAssign: return '%=';
      case TokenType.AmpersandAssign: return '&=';
      case TokenType.PipeAssign: return '|=';
      case TokenType.CaretAssign: return '^=';
      case TokenType.ShiftLeftAssign: return '<<=';
      case TokenType.ShiftRightAssign: return '>>=';
      default: return null;
    }
  }

  private getBinaryPrecedence(tok: Token): number {
    switch (tok.type) {
      case TokenType.OrOr: return 1;
      case TokenType.AndAnd: return 2;
      case TokenType.EqualEqual:
      case TokenType.BangEqual:
      case TokenType.LessThan:
      case TokenType.GreaterThan:
      case TokenType.LessEqual:
      case TokenType.GreaterEqual:
        return 3;
      case TokenType.Pipe: return 4;
      case TokenType.Caret: return 4;
      case TokenType.Ampersand: return 4;
      case TokenType.ShiftLeft:
      case TokenType.ShiftRight:
        return 5;
      case TokenType.Plus:
      case TokenType.Minus:
        return 6;
      case TokenType.Star:
      case TokenType.Slash:
      case TokenType.Percent:
        return 7;
      case TokenType.StarStar: return 8; // ** is right-associative, handled separately
      default:
        return 0;
    }
  }

  private mapBinaryOperator(op: string): string {
    return op;
  }

  private parseUnary(minPrec: number): ASTExpression {
    this.checkRecursionDepth();
    try {
      if (this.match(TokenType.Minus)) {
        this.advance();
        const sub = this.parseUnary(9);
        return {
          type: 'UnaryOperation',
          nodeType: 'UnaryOperation',
          operator: '-',
          subExpression: sub,
          prefix: true
        };
      }

      if (this.match(TokenType.Bang)) {
        this.advance();
        const sub = this.parseUnary(9);
        return {
          type: 'UnaryOperation',
          nodeType: 'UnaryOperation',
          operator: '!',
          subExpression: sub,
          prefix: true
        };
      }

      if (this.match(TokenType.Tilde)) {
        this.advance();
        const sub = this.parseUnary(9);
        return {
          type: 'UnaryOperation',
          nodeType: 'UnaryOperation',
          operator: '~',
          subExpression: sub,
          prefix: true
        };
      }

      if (this.match(TokenType.PlusPlus) || this.match(TokenType.MinusMinus)) {
        const op = this.current.value;
        this.advance();
        const sub = this.parseUnary(9);
        return {
          type: 'UnaryOperation',
          nodeType: 'UnaryOperation',
          operator: op === '++' ? '++' : '--',
          subExpression: sub,
          prefix: true
        };
      }

      return this.parsePrimary(minPrec);
    } finally {
      this.recursionDepth--;
    }
  }

  private parsePrimary(minPrec: number): ASTExpression {
    this.tick();
    // new Expression
    if (this.match(TokenType.KeywordNew) ||
        (this.match(TokenType.Identifier) && this.current.value === 'new')) {
      this.advance();
      const typeName = this.parseTypeName();
      if (!typeName) throw new ParserError('Expected type name after new', this.current);

      // Constructor call options: new Contract{salt: value, value: 1}()
      // These are used for CREATE2 salt or value transfers in deployment
      const options: Record<string, ASTExpression> = {};
      if (this.match(TokenType.LBrace)) {
        this.advance();
        while (!this.match(TokenType.RBrace) && !this.isAtEnd()) {
          const optKey = this.expect(TokenType.Identifier, 'Expected option name in new expression').value;
          this.expect(TokenType.Colon, `Expected : after ${optKey}`);
          options[optKey] = this.parseExpression();
          if (this.match(TokenType.Comma)) this.advance();
        }
        this.expect(TokenType.RBrace, 'Expected } after constructor call options');
      }

      let args: ASTExpression[] = [];
      if (this.match(TokenType.LParen)) {
        this.advance();
        while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
          args.push(this.parseExpression());
          if (this.match(TokenType.Comma)) this.advance();
        }
        this.expect(TokenType.RParen, 'Expected ) after constructor arguments');
      }

      return {
        type: 'NewExpression',
        nodeType: 'NewExpression',
        typeName,
        ...(Object.keys(options).length > 0 ? { options } : {})
      } as ASTExpression;
    }

    // Parenthesized expression or tuple
    if (this.match(TokenType.LParen)) {
      this.advance();

      // Check for empty tuple ()
      if (this.match(TokenType.RParen)) {
        this.advance();
        return {
          type: 'TupleExpression',
          nodeType: 'TupleExpression',
          components: []
        };
      }

      const components: ASTExpression[] = [];
      const hole: ASTExpression = {
        type: 'TupleExpression',
        nodeType: 'TupleExpression',
        components: []
      };

      // Parse tuple components. Handles:
      //   (a, b)            — normal tuple
      //   (, a, b)          — leading comma (first component is empty)
      //   (bytes memory data, uint256 code) — typed components
      //   (, bytes memory data)             — leading comma + typed component
      let tupleSafety = 0;
      const MAX_TUPLE_COMPONENTS = 10000;

      for (;;) {
        const posBefore = this.pos;

        // Leading comma or trailing comma after a hole: skip empty component
        if (this.match(TokenType.Comma)) {
          components.push(hole);
          this.advance(); // consume comma
          continue;
        }

        // Check if this is a typed tuple component: uint256 varName, bool success, etc.
        if (this.isTypeNameStart()) {
          const typeStart = this.pos;
          const typeName = this.parseTypeName();
          // Type names may have a storage location before the variable name
          this.skipStorageLocation();
          if (typeName && this.match(TokenType.Identifier)) {
            // We have a type name followed by a variable name — it's a typed tuple component
            const varName = this.current.value;
            this.advance();
            components.push({
              type: 'VariableDeclaration',
              nodeType: 'VariableDeclaration',
              scope: 0,
              declared: 0,
              isStateVar: false,
              isIndexed: false,
              isVisibleInStruct: false,
              isConstant: false,
              isImmutable: false,
              name: varName,
              typeName: typeName,
              value: null,
              storageLocation: 'default',
              stateVariableVisibility: 'default',
              functionVisibility: 'public',
              slot: null,
              offset: null
            } as any);
          } else {
            // No variable name — backtrack and parse as expression
            this.pos = typeStart;
            components.push(this.parseExpression());
          }
        } else {
          // Parse a plain expression component
          components.push(this.parseExpression());
        }

        if (this.pos === posBefore) {
          this.advance(); // Prevent infinite loop on malformed input
        }

        tupleSafety++;
        if (tupleSafety > MAX_TUPLE_COMPONENTS) {
          throw new ParserError(
            `Too many tuple components (>${MAX_TUPLE_COMPONENTS}) — possible malformed tuple`,
            this.current
          );
        }

        // After a component, expect comma (for multi-component tuple) or RParen
        if (this.match(TokenType.RParen)) {
          this.advance();
          break;
        }
        if (this.match(TokenType.Comma)) {
          this.advance();
          // If RParen immediately follows, the last component was a trailing comma — pop the hole
          // Actually, don't pop — trailing commas mean the last component is still empty
          if (this.match(TokenType.RParen)) {
            this.advance();
            break;
          }
          continue;
        }

        // Neither comma nor RParen — malformed, try to recover
        break;
      }

      // Single expression in parentheses with no trailing comma: (expr)
      if (components.length === 1) {
        return components[0];
      }

      return {
        type: 'TupleExpression',
        nodeType: 'TupleExpression',
        components
      };
    }

    // Literals
    if (this.match(TokenType.NumberLiteral)) {
      const value = this.advance().value;
      // Solidity number literals can have unit suffixes: wei, gwei, ether, etc.
      // These are tokenized as separate Identifier tokens after the number.
      // Consume the unit suffix if present so it doesn't get misinterpreted.
      let unit = '';
      if (this.match(TokenType.Identifier) &&
          ['wei', 'gwei', 'szabo', 'finney', 'ether', 'seconds', 'minutes', 'hours', 'days', 'weeks'].includes(this.current.value.toLowerCase())) {
        unit = this.current.value;
        this.advance();
      }
      return {
        type: 'Literal',
        nodeType: 'Literal',
        value: this.parseNumber(value),
        valueType: 'number',
        hexValue: null,
        unit: unit || null
      } as any;
    }

    if (this.match(TokenType.StringLiteral)) {
      const raw = this.advance().value;
      const str = raw.replace(/^["']|["']$/g, '');
      return {
        type: 'Literal',
        nodeType: 'Literal',
        value: str,
        valueType: 'string',
        hexValue: null
      };
    }

    if (this.match(TokenType.HexLiteral)) {
      const raw = this.advance().value;
      return {
        type: 'Literal',
        nodeType: 'Literal',
        value: raw,
        valueType: 'hex',
        hexValue: raw
      };
    }

    // Booleans true/false
    if (this.match(TokenType.KeywordTrue)) {
      this.advance();
      return {
        type: 'Literal', nodeType: 'Literal', value: true, valueType: 'bool', hexValue: null
      };
    }
    if (this.match(TokenType.KeywordFalse)) {
      this.advance();
      return {
        type: 'Literal', nodeType: 'Literal', value: false, valueType: 'bool', hexValue: null
      };
    }

    // Array literal: [expr, expr, ...] or [] (empty array)
    if (this.match(TokenType.LBracket)) {
      this.advance();
      const elements: ASTExpression[] = [];
      // Empty array: []
      if (!this.match(TokenType.RBracket)) {
        while (!this.match(TokenType.RBracket) && !this.isAtEnd()) {
          try {
            elements.push(this.parseExpression());
            // After parsing an element, expect comma or closing bracket
            if (this.match(TokenType.Comma)) {
              this.advance();
            } else if (this.match(TokenType.RBracket)) {
              break;
            } else {
              // Element parsed but next token isn't comma or ] — likely
              // malformed syntax (e.g., truncated 0xa... ). Skip to next comma or ].
              while (!this.match(TokenType.RBracket) && !this.match(TokenType.Comma) && !this.isAtEnd()) {
                this.advance();
              }
              if (this.match(TokenType.Comma)) this.advance();
            }
          } catch {
            // If an element can't be parsed (e.g., truncated placeholder like
            // 0xa... in test contracts), skip to the next comma or closing bracket
            // so the parser recovers rather than failing the entire contract.
            while (!this.match(TokenType.RBracket) && !this.match(TokenType.Comma) && !this.isAtEnd()) {
              this.advance();
            }
            if (this.match(TokenType.Comma)) this.advance();
          }
        }
      }
      this.expect(TokenType.RBracket, 'Expected ] to close array literal');
      return {
        type: 'ArrayLiteral',
        nodeType: 'ArrayLiteral',
        elements
      } as any;
    }

    // payable(...) type cast expression
    // e.g. payable(msg.sender).transfer(amount)
    if (this.match(TokenType.KeywordPayable)) {
      this.advance(); // consume 'payable'
      this.expect(TokenType.LParen, 'Expected ( after payable');

      const args: ASTExpression[] = [];
      if (!this.match(TokenType.RParen)) {
        let argSafety = 0;
        const MAX_ARGS = 10000;
        while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
          const posBefore = this.pos;
          args.push(this.parseExpression());
          if (this.pos === posBefore) {
            this.advance(); // Prevent infinite loop
          }
          if (this.match(TokenType.Comma)) this.advance();
          argSafety++;
          if (argSafety > MAX_ARGS) {
            throw new ParserError(`Too many arguments in payable() call`, this.current);
          }
        }
      }
      this.expect(TokenType.RParen, 'Expected ) after payable arguments');

      let expr: ASTExpression = {
        type: 'FunctionCall',
        nodeType: 'FunctionCall',
        names: [],
        arguments: args,
        expression: {
          type: 'Identifier',
          nodeType: 'Identifier',
          name: 'payable',
          referencedDeclaration: null,
          isTainted: false,
          isConstant: false
        },
        kind: 'typeConversion',
        isExternalCall: false,
        isLowLevelCall: false,
        isHighLevelCall: false,
        callValue: null,
        callGas: null,
        isPayable: true,
        targetTainted: this.isTainted(args[0]),
        valueTainted: this.isTainted(args[0]),
        sourceUnits: [],
        isRef: false,
        referencedDeclaration: null
      } as ASTFunctionCall;

      // Handle postfix operations on payable() result: .transfer(), .call(), etc.
      while (true) {
        this.tick();
        if (this.match(TokenType.Dot)) {
          this.advance();
          // Use lenient field name parsing — the token after . may be a keyword
          // (memory, storage, etc.) in test contracts. Accept it as a field name.
          if (this.isAtEnd()) {
            break; // EOF after dot — stop parsing
          }
          const fieldName = this.current.type === TokenType.Identifier
            ? this.expect(TokenType.Identifier, 'Expected field name after .').value
            : this.advance().value || 'unknown';

          // Check for low-level call: .call{value: 1, gas: 1000}() or .call()
          if (this.match(TokenType.LParen) || this.match(TokenType.LBrace)) {
            const options: Record<string, ASTExpression> = {};
            if (this.match(TokenType.LBrace)) {
              this.advance();
              while (!this.match(TokenType.RBrace) && !this.isAtEnd()) {
                const optKey = this.expect(TokenType.Identifier, 'Expected option name').value;
                this.expect(TokenType.Colon, `Expected : after ${optKey}`);
                options[optKey] = this.parseExpression();
                if (this.match(TokenType.Comma)) this.advance();
              }
              this.expect(TokenType.RBrace, 'Expected } after call options');
            }

            this.expect(TokenType.LParen, 'Expected ( after call options');

            const callArgs: ASTExpression[] = [];
            if (!this.match(TokenType.RParen)) {
              while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
                callArgs.push(this.parseExpression());
                if (this.match(TokenType.Comma)) this.advance();
              }
            }
            this.expectOrEof(TokenType.RParen, 'Expected ) after call arguments');

            expr = {
              type: 'FunctionCall',
              nodeType: 'FunctionCall',
              names: [],
              arguments: callArgs,
              expression: {
                type: 'MemberAccess',
                nodeType: 'MemberAccess',
                name: fieldName,
                referencedDeclaration: null,
                expression: expr,
                isMsgSender: false,
                isMsgValue: false,
                isTxOrigin: false,
                isBlockTimestamp: false,
                isBlockNumber: false,
                isThis: false,
                isTainted: this.isTainted(expr)
              } as any,
              kind: 'functionCall',
              isExternalCall: ['call', 'staticcall', 'delegatecall', 'send', 'transfer'].includes(fieldName),
              isLowLevelCall: ['call', 'staticcall', 'delegatecall', 'send'].includes(fieldName),
              isHighLevelCall: !['call', 'staticcall', 'delegatecall', 'send', 'transfer'].includes(fieldName),
              callValue: options['value'] || null,
              callGas: options['gas'] || null,
              isPayable: !!options['value'],
              targetTainted: this.isTainted(expr),
              valueTainted: options['value'] ? this.isTainted(options['value']) : false
            } as ASTFunctionCall;
          } else {
            // Member access: expr.fieldName (without call)
            expr = {
              type: 'MemberAccess',
              nodeType: 'MemberAccess',
              name: fieldName,
              referencedDeclaration: null,
              expression: expr,
              isMsgSender: (expr.type === 'MemberAccess' && expr.name === 'msg' && fieldName === 'sender') ||
                            (expr.type === 'Identifier' && expr.name === 'msg' && fieldName === 'sender'),
              isMsgValue: (expr.type === 'MemberAccess' && expr.name === 'msg' && fieldName === 'value') ||
                          (expr.type === 'Identifier' && expr.name === 'msg' && fieldName === 'value'),
              isTxOrigin: (expr.type === 'MemberAccess' && expr.name === 'tx' && fieldName === 'origin') ||
                          (expr.type === 'Identifier' && expr.name === 'tx' && fieldName === 'origin'),
              isBlockTimestamp: false,
              isBlockNumber: false,
              isThis: false,
              isTainted: this.isTainted(expr)
            };
          }
        } else if (this.match(TokenType.LBracket)) {
          this.advance();
          const index = this.parseExpression();
          this.expect(TokenType.RBracket, 'Expected ] after index');
          expr = {
            type: 'IndexAccess',
            nodeType: 'IndexAccess',
            baseExpression: expr,
            indexExpression: index,
            isTainted: this.isTainted(expr) || this.isTainted(index)
          } as any;
        } else if (this.match(TokenType.LParen)) {
          this.advance();
          const args: ASTExpression[] = [];
          let argSafety = 0;
          const MAX_ARGS = 10000;
          while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
            const posBefore = this.pos;
            args.push(this.parseExpression());
            if (this.pos === posBefore) {
              this.advance(); // Prevent infinite loop on malformed input
            }
            if (this.match(TokenType.Comma)) this.advance();
            argSafety++;
            if (argSafety > MAX_ARGS) {
              throw new ParserError(`Too many arguments`, this.current);
            }
          }
          this.expectOrEof(TokenType.RParen, 'Expected ) after function arguments');
          expr = {
            type: 'FunctionCall',
            nodeType: 'FunctionCall',
            names: [],
            arguments: args,
            expression: expr,
            kind: 'functionCall',
            isExternalCall: false,
            isLowLevelCall: false,
            isHighLevelCall: false,
            callValue: null,
            callGas: null,
            isPayable: false,
            targetTainted: false,
            valueTainted: false
          } as ASTFunctionCall;
        } else if (this.match(TokenType.PlusPlus)) {
          this.advance();
          expr = {
            type: 'UnaryOperation',
            nodeType: 'UnaryOperation',
            operator: '++',
            subExpression: expr,
            prefix: false
          } as any;
        } else if (this.match(TokenType.MinusMinus)) {
          this.advance();
          expr = {
            type: 'UnaryOperation',
            nodeType: 'UnaryOperation',
            operator: '--',
            subExpression: expr,
            prefix: false
          } as any;
        } else {
          break;
        }
      }

      return expr;
    }

    // Identifiers and member access (also handles 'this' keyword so it goes
    // through the same postfix chain: .selector, [index], call(), etc.)
    // Also handle 'type' keyword (tokenized as KeywordApply) which is a built-in
    // used as type(TypeName).property — e.g., type(uint256).max, type(Contract).creationCode
    if (this.match(TokenType.Identifier) && this.current.value === 'hex' &&
        this.peek(1).type === TokenType.StringLiteral) {
      // hex"string" — Solidity hex string literal (e.g., hex"4f1f05bc...")
      this.advance(); // consume 'hex'
      const raw = this.advance().value;
      const str = raw.replace(/^["']|["']$/g, '');
      return {
        type: 'Literal',
        nodeType: 'Literal',
        value: str,
        valueType: 'string',
        hexValue: str,
        hexString: true
      } as any;
    }

    if (this.match(TokenType.Identifier) || this.match(TokenType.KeywordThis) ||
        (this.match(TokenType.KeywordApply) && this.current.value === 'type')) {
      const name = this.advance().value;

      let expr: ASTExpression = this.resolveIdentifier(name);

      // Postfix operations: .field, [index], (args), ++, --
      while (true) {
        this.tick();
        if (this.match(TokenType.Dot)) {
          this.advance();
          // Use lenient field name parsing — the token after . may be a keyword
          // (memory, storage, etc.) in test contracts. Accept it as a field name.
          if (this.isAtEnd()) {
            break; // EOF after dot — stop parsing
          }
          const fieldName = this.current.type === TokenType.Identifier
            ? this.expect(TokenType.Identifier, 'Expected field name after .').value
            : this.advance().value || 'unknown';

          // Check for low-level call: .call{value: 1, gas: 1000}() or .call()
          if (this.match(TokenType.LParen) || this.match(TokenType.LBrace)) {
            // Parse call options {value: ..., gas: ...} if present
            const options: Record<string, ASTExpression> = {};
            if (this.match(TokenType.LBrace)) {
              this.advance();
              while (!this.match(TokenType.RBrace) && !this.isAtEnd()) {
                const optKey = this.expect(TokenType.Identifier, 'Expected option name').value;
                this.expect(TokenType.Colon, `Expected : after ${optKey}`);
                options[optKey] = this.parseExpression();
                if (this.match(TokenType.Comma)) this.advance();
              }
              this.expect(TokenType.RBrace, 'Expected } after call options');
            }

            this.expect(TokenType.LParen, 'Expected ( after call options');
            // expect already consumed the LParen, don't advance again

            const args: ASTExpression[] = [];
            if (!this.match(TokenType.RParen)) {
              let argSafety = 0;
              const MAX_ARGS = 10000;
              while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
                const posBefore = this.pos;
                args.push(this.parseExpression());
                if (this.pos === posBefore) {
                  // Parser didn't consume any tokens — advance to avoid
                  // infinite loop on malformed input
                  this.advance();
                }
                if (this.match(TokenType.Comma)) this.advance();
                argSafety++;
                if (argSafety > MAX_ARGS) {
                  throw new ParserError(
                    `Too many arguments (>${MAX_ARGS}) — possible malformed call expression`,
                    this.current
                  );
                }
              }
            }
            this.expectOrEof(TokenType.RParen, 'Expected ) after call arguments');

            const isLowLevel = ['call', 'staticcall', 'delegatecall', 'send'].includes(fieldName);
            const isExt = ['call', 'staticcall', 'delegatecall', 'send', 'transfer'].includes(fieldName);
            const callExpr: ASTFunctionCall = {
              type: 'FunctionCall',
              nodeType: 'FunctionCall',
              names: [],
              arguments: args,
              expression: expr,
              kind: 'functionCall',
              isExternalCall: isExt,
              isLowLevelCall: isLowLevel,
              // Without type information we can't know if the target is a contract.
              // Only mark transfer as high-level (it always sends ETH to an address);
              // everything else is unknown without type resolution.
              isHighLevelCall: fieldName === 'transfer',
              callValue: options['value'] || null,
              callGas: options['gas'] || null,
              isPayable: !!options['value'],
              targetTainted: this.isTainted(expr),
              valueTainted: options['value'] ? this.isTainted(options['value']) : false
            };

            expr = callExpr;
          } else {
            // Member access: expr.fieldName
            // Check for legacy .call.value(x)() pattern: .value is a modifier, not a real call
            // It sets the value to send in the subsequent .call()()
            if (this.match(TokenType.LParen) && fieldName === 'value') {
              // Legacy pattern: addr.call.value(x)()
              // .value(x) is a member access with arguments, not a function call
              this.advance();
              const valueArgs: ASTExpression[] = [];
              if (!this.match(TokenType.RParen)) {
                let argSafety = 0;
                while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
                  const posBefore = this.pos;
                  valueArgs.push(this.parseExpression());
                  if (this.pos === posBefore) this.advance();
                  if (this.match(TokenType.Comma)) this.advance();
                  argSafety++;
                  if (argSafety > 10000) {
                    throw new ParserError('Too many arguments in .value()', this.current);
                  }
                }
              }
              this.expect(TokenType.RParen, 'Expected ) after .value arguments');

              expr = {
                type: 'MemberAccess',
                nodeType: 'MemberAccess',
                name: fieldName,
                referencedDeclaration: null,
                expression: expr,
                isMsgSender: false,
                isMsgValue: false,
                isTxOrigin: false,
                isBlockTimestamp: false,
                isBlockNumber: false,
                isThis: false,
                isTainted: this.isTainted(expr),
                // Legacy .call.value(x)() pattern — store the value
                callValue: valueArgs[0] || null
              } as any;
            } else {
              expr = {
                type: 'MemberAccess',
                nodeType: 'MemberAccess',
                name: fieldName,
                referencedDeclaration: null,
                expression: expr,
                isMsgSender: (expr.type === 'MemberAccess' && expr.name === 'msg' && fieldName === 'sender') ||
                              (expr.type === 'Identifier' && expr.name === 'msg' && fieldName === 'sender'),
                isMsgValue: (expr.type === 'MemberAccess' && expr.name === 'msg' && fieldName === 'value') ||
                            (expr.type === 'Identifier' && expr.name === 'msg' && fieldName === 'value'),
                isTxOrigin: (expr.type === 'MemberAccess' && expr.name === 'tx' && fieldName === 'origin') ||
                            (expr.type === 'Identifier' && expr.name === 'tx' && fieldName === 'origin'),
                isBlockTimestamp: (expr.type === 'MemberAccess' && expr.name === 'block' && fieldName === 'timestamp') ||
                                 (expr.type === 'Identifier' && expr.name === 'blockhash'),
                isBlockNumber: expr.type === 'MemberAccess' && expr.name === 'block' && fieldName === 'number',
                isThis: expr.type === 'Identifier' && expr.name === 'this',
                isTainted: this.isTainted(expr)
              };
            }
          }
        } else if (this.match(TokenType.LBracket)) {
          this.advance();
          const index = this.parseExpression();
          this.expect(TokenType.RBracket, 'Expected ] after index');

          expr = {
            type: 'IndexAccess',
            nodeType: 'IndexAccess',
            baseExpression: expr,
            indexExpression: index,
            isTainted: this.isTainted(expr) || this.isTainted(index)
          } as ASTIndexAccess;
        } else if (this.match(TokenType.LParen)) {
          this.advance();

          // Handle struct constructor with named args: Foo({name: value, ...})
          // This is different from call options: .call{value: ...}()
          if (this.match(TokenType.LBrace)) {
            this.advance(); // consume {
            const namedArgs: Record<string, ASTExpression> = {};
            let argSafety = 0;
            const MAX_NAMED_ARGS = 10000;
            while (!this.match(TokenType.RBrace) && !this.isAtEnd()) {
              const posBefore = this.pos;
              const argName = this.expect(TokenType.Identifier, 'Expected named argument name in struct constructor').value;
              this.expectOrEof(TokenType.Colon, `Expected : after named argument ${argName}`);
              namedArgs[argName] = this.parseExpression();
              if (this.pos === posBefore) {
                this.advance(); // Prevent infinite loop
              }
              if (this.match(TokenType.Comma)) this.advance();
              argSafety++;
              if (argSafety > MAX_NAMED_ARGS) {
                throw new ParserError(`Too many named arguments`, this.current);
              }
            }
            this.expectOrEof(TokenType.RBrace, 'Expected } after named arguments');
            // Consume the closing ) of the function call
            this.expectOrEof(TokenType.RParen, 'Expected ) after named arguments');
            expr = {
              type: 'FunctionCall',
              nodeType: 'FunctionCall',
              names: Object.keys(namedArgs),
              arguments: Object.values(namedArgs),
              expression: expr,
              kind: 'functionCall',
              isExternalCall: false,
              isLowLevelCall: false,
              isHighLevelCall: false,
              callValue: null,
              callGas: null,
              isPayable: false,
              targetTainted: false,
              valueTainted: false
            } as ASTFunctionCall;
          } else {
            // Regular function call: Foo(arg1, arg2, ...)
            // Also handles named args: Foo(name: value1, name2: value2)
            // Found in test contracts and struct constructors without braces.
            const args: ASTExpression[] = [];
            const argNames: string[] = [];
            let argSafety = 0;
            const MAX_ARGS = 10000;
            while (!this.match(TokenType.RParen) && !this.isAtEnd()) {
              const posBefore = this.pos;
              // Check for named argument: Identifier followed by :
              if (this.match(TokenType.Identifier) && this.peek(1).type === TokenType.Colon) {
                const argName = this.current.value;
                this.advance(); // consume identifier
                this.advance(); // consume ':'
                argNames.push(argName);
                args.push(this.parseExpression());
              } else {
                args.push(this.parseExpression());
                argNames.push('');
              }
              if (this.pos === posBefore) {
                // Parser didn't consume any tokens — advance to avoid infinite loop
                this.advance();
              }
              if (this.match(TokenType.Comma)) this.advance();
              argSafety++;
              if (argSafety > MAX_ARGS) {
                throw new ParserError(
                  `Too many arguments (>${MAX_ARGS}) — possible malformed call expression`,
                  this.current
                );
              }
            }
            this.expectOrEof(TokenType.RParen, 'Expected ) after function arguments');

            expr = {
              type: 'FunctionCall',
              nodeType: 'FunctionCall',
              names: argNames.filter(n => n !== ''),
              arguments: args,
              expression: expr,
              kind: 'functionCall',
              isExternalCall: false,
              isLowLevelCall: false,
              isHighLevelCall: false,
              callValue: null,
              callGas: null,
              isPayable: false,
              targetTainted: false,
              valueTainted: false
            } as ASTFunctionCall;
          }
        } else if (this.match(TokenType.PlusPlus)) {
          this.advance();
          expr = {
            type: 'UnaryOperation',
            nodeType: 'UnaryOperation',
            operator: '++',
            subExpression: expr,
            prefix: false
          } as ASTUnaryOperation;
        } else if (this.match(TokenType.MinusMinus)) {
          this.advance();
          expr = {
            type: 'UnaryOperation',
            nodeType: 'UnaryOperation',
            operator: '--',
            subExpression: expr,
            prefix: false
          } as ASTUnaryOperation;
        } else {
          break;
        }
      }

      return expr;
    }

    // 'delete'
    if (this.match(TokenType.KeywordDelete)) {
      this.advance();
      const variable = this.parsePrimary(10);
      return {
        type: 'Delete',
        nodeType: 'Delete',
        variable
      } as ASTDelete;
    }

    // Fallback: return a literal with empty value
    return {
      type: 'Literal',
      nodeType: 'Literal',
      value: null,
      valueType: null,
      hexValue: null
    };
  }

  private resolveIdentifier(name: string): ASTExpression {
    // Check for special identifiers
    const isMsgSender = name === 'msg' && false; // handled in member access
    const isConstant = ['block', 'msg', 'tx', 'abi', 'gas', 'assert', 'require', 'revert'].includes(name);

    return {
      type: 'Identifier',
      nodeType: 'Identifier',
      name,
      referencedDeclaration: null,
      isTainted: name === 'msg' || name === 'tx', // These carry user input
      isConstant
    };
  }

  private parseNumber(str: string): string | number | boolean | null {
    // Check if hex
    if (str.startsWith('0x') || str.startsWith('0X')) {
      const hexStr = str.slice(2).replace(/_/g, '');
      if (hexStr.length > 64) {
        // Extremely large hex literal — return as string to avoid overflow
        return str;
      }
      return parseInt(hexStr, 16);
    }

    // Check for scientific notation (e.g., 1e18) before stripping unit suffix,
    // since 'e' is alphabetic and would be incorrectly captured as a unit.
    if (/[eE]/.test(str)) {
      const floatVal = parseFloat(str.replace(/_/g, ''));
      // If the value is very large, return as string to avoid precision loss
      if (!isFinite(floatVal) || Math.abs(floatVal) > Number.MAX_SAFE_INTEGER) {
        return str.replace(/_/g, '');
      }
      return floatVal;
    }

    // Remove underscores from digit groups (Solidity allows 1_000_000)
    const cleanStr = str.replace(/_/g, '');

    // Check if float (has a decimal point)
    if (cleanStr.includes('.')) {
      return parseFloat(cleanStr);
    }

    // Integer literal
    if (cleanStr.length > 18) {
      // Very long integer literal — return as string to avoid precision loss
      // and potential "Invalid array length" if used as an array index
      return cleanStr;
    }
    return parseInt(cleanStr, 10);
  }

  // ===========================================================================
  // Taint analysis helpers
  // ===========================================================================

  /**
   * Check if an expression contains tainted input (calldata, msg.sender, msg.value, etc.).
   */
  private containsTaintedInput(expr: ASTExpression): boolean {
    return this.isTainted(expr);
  }

  private isTainted(expr: ASTExpression): boolean {
    switch (expr.type) {
      case 'Identifier':
        return expr.isTainted;
      case 'MemberAccess':
        return expr.isMsgSender || expr.isMsgValue || expr.isTxOrigin || expr.isTainted;
      case 'IndexAccess':
        return expr.isTainted || this.isTainted(expr.baseExpression) || this.isTainted(expr.indexExpression);
      case 'FunctionCall':
        if (expr.arguments) {
          for (const arg of expr.arguments) {
            if (this.isTainted(arg)) return true;
          }
        }
        if (expr.expression) {
          return this.isTainted(expr.expression);
        }
        return false;
      case 'BinaryOperation':
        return this.isTainted(expr.left) || this.isTainted(expr.right);
      case 'TupleExpression':
        return expr.components.some(c => this.isTainted(c));
      case 'UnaryOperation':
        return this.isTainted(expr.subExpression);
      case 'Assignment':
        return this.isTainted(expr.right);
      case 'Conditional':
        return this.isTainted(expr.condition) || this.isTainted(expr.trueExpression) ||
               (expr.falseExpression !== null && this.isTainted(expr.falseExpression));
      default:
        return false;
    }
  }

}

// Re-export tokenize for external use
export { tokenize };
