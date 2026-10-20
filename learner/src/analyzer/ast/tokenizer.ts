/**
 * Solidity tokenizer — converts raw source text into typed tokens.
 *
 * Handles:
 * - Keywords (contract, function, public, etc.)
 * - Operators (including compound assignment like +=, -=, etc.)
 * - Literals (numbers, strings, addresses, hex)
 * - Identifiers
 * - Comments (// and slash-star comments — skipped, but line tracking preserved)
 * - Pragma versions and NatSpec
 */

export enum TokenType {
  // Keywords
  KeywordAbstract,
  KeywordAlias,
  KeywordApply,
  KeywordArgs,
  KeywordAs,
  KeywordAssembly,
  KeywordBreak,
  KeywordCalldata,
  KeywordCatch,
  KeywordConstant,
  KeywordConstructor,
  KeywordContract,
  KeywordContinue,
  KeywordDefault,
  KeywordDefine,
  KeywordDelete,
  KeywordDo,
  KeywordElse,
  KeywordEmit,
  KeywordEnum,
  KeywordError,
  KeywordEvent,
  KeywordExternal,
  KeywordFallible,
  KeywordFalse,
  KeywordFallback,
  KeywordFor,
  KeywordFrom,
  KeywordFunction,
  KeywordGlobal,
  KeywordGot,
  KeywordIndexed,
  KeywordInherited,
  KeywordInterface,
  KeywordInternal,
  KeywordIs,
  KeywordLambda,
  KeywordLibrary,
  KeywordModifier,
  KeywordMut,
  KeywordNew,
  KeywordOverride,
  KeywordParametros,
  KeywordPragma,
  KeywordPayable,
  KeywordPurity,
  KeywordRaise,
  KeywordReturn,
  KeywordReturns,
  KeywordRevert,
  KeywordSelf,
  KeywordShadow,
  KeywordStorage,
  KeywordStruct,
  KeywordSuccess,
  KeywordSuper,
  KeywordThis,
  KeywordThrow,
  KeywordTrue,
  KeywordTry,
  KeywordType,
  KeywordUsing,
  KeywordValue,
  KeywordVar,
  KeywordWhile,
  KeywordImmutable,
  KeywordReceive,
  KeywordUndef,
  KeywordVirtual,
  KeywordPure,
  KeywordView,
  KeywordFunctionKind,
  KeywordImport,
  Increment,
  Decrement,

  // Visibility modifiers
  KeywordPublic,
  KeywordPrivate,
  KeywordMemory,

  // Primitive types
  KeywordString,
  KeywordInt,
  KeywordUint,
  KeywordBool,
  KeywordAddress,
  KeywordBytes,
  KeywordReal,
  KeywordByte,

  // Tokens
  Identifier,
  NumberLiteral,
  StringLiteral,
  AddressLiteral,
  HexLiteral,
  BooleanLiteral,

  // Operators
  Plus,           // +
  Minus,          // -
  Star,           // *
  Slash,          // /
  Percent,        // %
  Ampersand,      // &
  Pipe,           // |
  Caret,          // ^
  Tilde,          // ~
  ShiftLeft,      // <<
  ShiftRight,     // >>
  LessThan,       // <
  GreaterThan,    // >
  LessEqual,      // <=
  GreaterEqual,   // >=
  EqualEqual,     // ==
  BangEqual,      // !=
  Bang,           // !
  Assign,         // =
  PlusAssign,     // +=
  MinusAssign,    // -=
  StarAssign,     // *=
  SlashAssign,    // /=
  PercentAssign,  // %=
  AmpersandAssign, // &=
  PipeAssign,     // |=
  CaretAssign,    // ^=
  ShiftLeftAssign, // <<=
  ShiftRightAssign, // >>=
  StarStar,       // ** (exponentiation, right-associative)
  AndAnd,         // &&
  OrOr,           // ||
  PlusPlus,       // ++
  MinusMinus,     // --
  Comma,          // ,
  Semicolon,      // ;
  Colon,          // :
  Question,       // ?
  Dot,            // .
  Arrow,          // ->
  FatArrow,       // =>

  // Brackets
  LParen,         // (
  RParen,         // )
  LBracket,       // [
  RBracket,       // ]
  LBrace,         // {
  RBrace,         // }

  // Special
  EOF,
  Error,
}

export interface Token {
  type: TokenType;
  value: string;
  offset: number;
  line: number;
  col: number;
}

export class TokenizerError extends Error {
  public offset: number;
  public line: number;
  public col: number;

  constructor(message: string, offset: number, line: number, col: number) {
    super(`${message} at ${line}:${col} (offset ${offset})`);
    this.name = 'TokenizerError';
    this.offset = offset;
    this.line = line;
    this.col = col;
  }
}

// --- Solidity keywords mapping ---

const KEYWORDS: Record<string, TokenType> = {
  abstract: TokenType.KeywordAbstract,
  alias: TokenType.KeywordAlias,
  apply: TokenType.KeywordApply,
  args: TokenType.KeywordArgs,
  as: TokenType.KeywordAs,
  assembly: TokenType.KeywordAssembly,
  break: TokenType.KeywordBreak,
  calldata: TokenType.KeywordCalldata,
  catch: TokenType.KeywordCatch,
  constant: TokenType.KeywordConstant,
  constructor: TokenType.KeywordConstructor,
  contract: TokenType.KeywordContract,
  continue: TokenType.KeywordContinue,
  default: TokenType.KeywordDefault,
  define: TokenType.KeywordDefine,
  delete: TokenType.KeywordDelete,
  do: TokenType.KeywordDo,
  else: TokenType.KeywordElse,
  emit: TokenType.KeywordEmit,
  enum: TokenType.KeywordEnum,
  error: TokenType.KeywordError,
  event: TokenType.KeywordEvent,
  external: TokenType.KeywordExternal,
  false: TokenType.KeywordFalse,
  fallback: TokenType.KeywordFallback,
  global: TokenType.KeywordGlobal,
  for: TokenType.KeywordFor,
  function: TokenType.KeywordFunction,
  immutable: TokenType.KeywordImmutable,
  import: TokenType.KeywordImport,
  inherited: TokenType.KeywordInherited,
  interface: TokenType.KeywordInterface,
  internal: TokenType.KeywordInternal,
  is: TokenType.KeywordIs,
  lambda: TokenType.KeywordLambda,
  library: TokenType.KeywordLibrary,
  modifier: TokenType.KeywordModifier,
  mut: TokenType.KeywordMut,
  new: TokenType.KeywordNew,
  override: TokenType.KeywordOverride,
  public: TokenType.KeywordPublic,
  private: TokenType.KeywordPrivate,
  parametros: TokenType.KeywordParametros,
  memory: TokenType.KeywordMemory,
  pragma: TokenType.KeywordPragma,
  payable: TokenType.KeywordPayable,
  purity: TokenType.KeywordPurity,
  pure: TokenType.KeywordPure,
  return: TokenType.KeywordReturn,
  returns: TokenType.KeywordReturns,
  revert: TokenType.KeywordRevert,
  self: TokenType.KeywordSelf,
  storage: TokenType.KeywordStorage,
  struct: TokenType.KeywordStruct,
  super: TokenType.KeywordSuper,
  this: TokenType.KeywordThis,
  throw: TokenType.KeywordThrow,
  true: TokenType.KeywordTrue,
  try: TokenType.KeywordTry,
  type: TokenType.KeywordApply,
  using: TokenType.KeywordUsing,
  var: TokenType.KeywordVar,
  view: TokenType.KeywordView,
  while: TokenType.KeywordWhile,
  virtual: TokenType.KeywordVirtual,
  receive: TokenType.KeywordReceive,
};

/**
 * Convert a Solidity keyword string to its token type.
 */
function keywordType(name: string): TokenType | null {
  return KEYWORDS[name] ?? null;
}

/**
 * Check if a string is a valid Solidity identifier.
 */
function isValidIdentChar(ch: string): boolean {
  // Solidity identifiers: letters, digits, underscore, and dollar sign ($).
  // The $ character is used in modern Solidity (0.7+) for internal/selector
  // variables and assembly labels. Without accepting $, the tokenizer throws
  // "Unknown character '$'" on valid modern Solidity code.
  return (
    (ch >= 'a' && ch <= 'z') ||
    (ch >= 'A' && ch <= 'Z') ||
    ch === '_' ||
    ch === '$' ||
    (ch >= '0' && ch <= '9')
  );
}

/**
 * Tokenize Solidity source code.
 * Strips comments but preserves line/column tracking.
 */
export function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  let line = 1;
  let col = 1;

  // Strip BOM (Byte Order Mark) if present — common in files from Windows editors
  if (source.charCodeAt(0) === 0xFEFF) {
    i = 1;
  }

  const advance = (): string => {
    const ch = source[i];
    if (ch === '\n') {
      line++;
      col = 1;
    } else {
      col++;
    }
    i++;
    return ch;
  };

  const saveToken = (type: TokenType, value: string, startOffset: number, startLine: number, startCol: number) => {
    tokens.push({ type, value, offset: startOffset, line: startLine, col: startCol });
  };

  while (i < source.length) {
    const ch = source[i];

    // --- Whitespace ---
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
      advance();
      continue;
    }

    // --- Comments ---
    if (ch === '/' && source[i + 1] === '/') {
      // Single-line comment
      while (i < source.length && source[i] !== '\n') advance();
      continue;
    }

    if (ch === '/' && source[i + 1] === '*') {
      // Multi-line comment
      const startLine = line;
      const startCol = col;
      advance(); // /
      advance(); // *
      while (i < source.length) {
        if (source[i] === '*' && source[i + 1] === '/') {
          advance(); // *
          advance(); // /
          break;
        }
        advance();
      }
      void startLine; void startCol;
      continue;
    }

    const startOffset = i;
    const startLine = line;
    const startCol = col;

    // --- Numbers ---
    if (ch >= '0' && ch <= '9') {
      let numStr = '';
      let isHex = false;

      // Hex number (0x...)
      if (source[i] === '0' && (source[i + 1] === 'x' || source[i + 1] === 'X')) {
        isHex = true;
        numStr += advance(); // 0
        numStr += advance(); // x
        const hexStartCol = col - 1;
        const hexStartLine = line;
        while (i < source.length && /[0-9a-fA-F]/.test(source[i])) {
          numStr += advance();
        }
        saveToken(TokenType.HexLiteral, numStr, startOffset, startLine, startCol);
        void isHex; void hexStartCol; void hexStartLine;
        continue;
      }

      // Decimal or float
      while (i < source.length &&
        (/[0-9]/.test(source[i]) ||
         source[i] === '.' ||
         source[i] === '_' ||
         /[eE]/.test(source[i]))) {
        numStr += advance();
      }

      // Handle unit suffixes (ether, gwei, etc.)
      if (i < source.length && isValidIdentChar(source[i])) {
        let unit = '';
        while (i < source.length && isValidIdentChar(source[i])) {
          unit += advance();
        }
        numStr += unit;
      }

      // Remove underscores for the value
      const cleanNum = numStr.replace(/_/g, '').replace(/[a-zA-Z]+$/, '');
      saveToken(TokenType.NumberLiteral, numStr, startOffset, startLine, startCol);
      void cleanNum;
      continue;
    }

    // --- Strings ---
    if (ch === '"' || ch === "'") {
      const quote = advance();
      let str = quote;
      while (i < source.length && source[i] !== quote) {
        if (source[i] === '\\' && i + 1 < source.length) {
          str += advance(); // backslash
          str += advance(); // escaped char
        } else {
          str += advance();
        }
      }
      if (i < source.length) {
        str += advance(); // closing quote
      }
      saveToken(TokenType.StringLiteral, str, startOffset, startLine, startCol);
      continue;
    }

    // --- Address literal (0x...) handled by number branch ---

    // --- Identifiers and keywords ---
    if (/[a-zA-Z_$]/.test(ch)) {
      let ident = '';
      while (i < source.length && isValidIdentChar(source[i])) {
        ident += advance();
      }

      // Check for prefixed string literals: hex"..." and unicode"..."
      if ((ident === 'hex' || ident === 'unicode') &&
          (source[i] === '"' || source[i] === "'")) {
        const quote = source[i];
        i++; col++; // consume opening quote
        let str = '';
        while (i < source.length && source[i] !== quote) {
          if (source[i] === '\\' && i + 1 < source.length) {
            str += advance(); // backslash
            str += advance(); // escaped char
          } else {
            str += advance();
          }
        }
        if (i < source.length) {
          i++; col++; // consume closing quote
        }
        if (ident === 'hex') {
          saveToken(TokenType.HexLiteral, str, startOffset, startLine, startCol);
        } else {
          saveToken(TokenType.StringLiteral, str, startOffset, startLine, startCol);
        }
        continue;
      }

      // Check if it's a keyword
      const kwType = keywordType(ident);
      if (kwType !== null) {
        saveToken(kwType, ident, startOffset, startLine, startCol);
      } else {
        saveToken(TokenType.Identifier, ident, startOffset, startLine, startCol);
      }
      continue;
    }

    // --- Multi-character operators ---
    const twoChar = source.slice(i, i + 2);
    const threeChar = source.slice(i, i + 3);

    // Check 3-char operators (none in Solidity, but slotting for future)
    void threeChar;

    // Check 2-char operators
    switch (twoChar) {
      case '==': advance(); advance(); saveToken(TokenType.EqualEqual, twoChar, startOffset, startLine, startCol); continue;
      case '!=': advance(); advance(); saveToken(TokenType.BangEqual, twoChar, startOffset, startLine, startCol); continue;
      case '<=': advance(); advance(); saveToken(TokenType.LessEqual, twoChar, startOffset, startLine, startCol); continue;
      case '>=': advance(); advance(); saveToken(TokenType.GreaterEqual, twoChar, startOffset, startLine, startCol); continue;
      case '->': advance(); advance(); saveToken(TokenType.Arrow, twoChar, startOffset, startLine, startCol); continue;
      case '=>': advance(); advance(); saveToken(TokenType.FatArrow, twoChar, startOffset, startLine, startCol); continue;
      case '&&': advance(); advance(); saveToken(TokenType.AndAnd, twoChar, startOffset, startLine, startCol); continue;
      case '||': advance(); advance(); saveToken(TokenType.OrOr, twoChar, startOffset, startLine, startCol); continue;
      case '++': advance(); advance(); saveToken(TokenType.PlusPlus, twoChar, startOffset, startLine, startCol); continue;
      case '--': advance(); advance(); saveToken(TokenType.MinusMinus, twoChar, startOffset, startLine, startCol); continue;
      case '+=': advance(); advance(); saveToken(TokenType.PlusAssign, twoChar, startOffset, startLine, startCol); continue;
      case '-=': advance(); advance(); saveToken(TokenType.MinusAssign, twoChar, startOffset, startLine, startCol); continue;
      case '*=': advance(); advance(); saveToken(TokenType.StarAssign, twoChar, startOffset, startLine, startCol); continue;
      case '**': advance(); advance(); saveToken(TokenType.StarStar, twoChar, startOffset, startLine, startCol); continue;
      case '/=': advance(); advance(); saveToken(TokenType.SlashAssign, twoChar, startOffset, startLine, startCol); continue;
      case '%=': advance(); advance(); saveToken(TokenType.PercentAssign, twoChar, startOffset, startLine, startCol); continue;
      case '&=': advance(); advance(); saveToken(TokenType.AmpersandAssign, twoChar, startOffset, startLine, startCol); continue;
      case '|=': advance(); advance(); saveToken(TokenType.PipeAssign, twoChar, startOffset, startLine, startCol); continue;
      case '^=': advance(); advance(); saveToken(TokenType.CaretAssign, twoChar, startOffset, startLine, startCol); continue;
      case '<<': advance(); advance(); saveToken(TokenType.ShiftLeft, twoChar, startOffset, startLine, startCol); continue;
      case '>>': advance(); advance(); saveToken(TokenType.ShiftRight, twoChar, startOffset, startLine, startCol); continue;
      case '<<=': case '>>=':
        advance(); advance(); advance();
        saveToken(twoChar === '<<=' ? TokenType.ShiftLeftAssign : TokenType.ShiftRightAssign, twoChar, startOffset, startLine, startCol);
        continue;
    }

    // --- Single-character operators ---
    switch (ch) {
      case '+': advance(); saveToken(TokenType.Plus, '+', startOffset, startLine, startCol); continue;
      case '-': advance(); saveToken(TokenType.Minus, '-', startOffset, startLine, startCol); continue;
      case '*': advance(); saveToken(TokenType.Star, '*', startOffset, startLine, startCol); continue;
      case '/': advance(); saveToken(TokenType.Slash, '/', startOffset, startLine, startCol); continue;
      case '%': advance(); saveToken(TokenType.Percent, '%', startOffset, startLine, startCol); continue;
      case '&': advance(); saveToken(TokenType.Ampersand, '&', startOffset, startLine, startCol); continue;
      case '|': advance(); saveToken(TokenType.Pipe, '|', startOffset, startLine, startCol); continue;
      case '^': advance(); saveToken(TokenType.Caret, '^', startOffset, startLine, startCol); continue;
      case '~': advance(); saveToken(TokenType.Tilde, '~', startOffset, startLine, startCol); continue;
      case '<': advance(); saveToken(TokenType.LessThan, '<', startOffset, startLine, startCol); continue;
      case '>': advance(); saveToken(TokenType.GreaterThan, '>', startOffset, startLine, startCol); continue;
      case '=': advance(); saveToken(TokenType.Assign, '=', startOffset, startLine, startCol); continue;
      case '!': advance(); saveToken(TokenType.Bang, '!', startOffset, startLine, startCol); continue;
      case ',': advance(); saveToken(TokenType.Comma, ',', startOffset, startLine, startCol); continue;
      case ';': advance(); saveToken(TokenType.Semicolon, ';', startOffset, startLine, startCol); continue;
      case ':': advance(); saveToken(TokenType.Colon, ':', startOffset, startLine, startCol); continue;
      case '?': advance(); saveToken(TokenType.Question, '?', startOffset, startLine, startCol); continue;
      case '.': advance(); saveToken(TokenType.Dot, '.', startOffset, startLine, startCol); continue;
      case '(': advance(); saveToken(TokenType.LParen, '(', startOffset, startLine, startCol); continue;
      case ')': advance(); saveToken(TokenType.RParen, ')', startOffset, startLine, startCol); continue;
      case '[': advance(); saveToken(TokenType.LBracket, '[', startOffset, startLine, startCol); continue;
      case ']': advance(); saveToken(TokenType.RBracket, ']', startOffset, startLine, startCol); continue;
      case '{': advance(); saveToken(TokenType.LBrace, '{', startOffset, startLine, startCol); continue;
      case '}': advance(); saveToken(TokenType.RBrace, '}', startOffset, startLine, startCol); continue;
    }

    // --- Smart quotes and common unicode punctuation ---
    // Source code copied from PDFs, websites, or word processors often contains
    // unicode "smart quotes" instead of ASCII quotes. Rather than throwing a
    // tokenizer error, normalize them to their ASCII equivalents so analysis
    // can proceed on real-world contract source.
    if (ch === '‘' || ch === '’' || ch === '‚' || ch === '‛') {
      // ' ' " ‚ „ → ASCII '
      const ascii = ch === '‛' || ch === '‚' ? '"' : "'";
      advance();
      let str = ascii;
      while (i < source.length && source[i] !== ascii && source[i] !== '‘' && source[i] !== '’' && source[i] !== '“' && source[i] !== '”') {
        if (source[i] === '\\' && i + 1 < source.length) {
          str += advance(); // backslash
          str += advance(); // escaped char
        } else {
          str += advance();
        }
      }
      if (i < source.length) {
        advance(); // consume closing quote (smart or ASCII)
      }
      saveToken(TokenType.StringLiteral, str, startOffset, startLine, startCol);
      continue;
    }
    if (ch === '“' || ch === '”') {
      // Double smart quotes: " " → ASCII "
      advance();
      let str = '"';
      while (i < source.length && source[i] !== '"' && source[i] !== '“' && source[i] !== '”') {
        if (source[i] === '\\' && i + 1 < source.length) {
          str += advance();
          str += advance();
        } else {
          str += advance();
        }
      }
      if (i < source.length) {
        advance(); // consume closing quote
      }
      saveToken(TokenType.StringLiteral, str, startOffset, startLine, startCol);
      continue;
    }

    // --- Unknown character ---
    throw new TokenizerError(
      `Unknown character '${ch}'`,
      startOffset,
      startLine,
      startCol
    );
  }

  saveToken(TokenType.EOF, '', source.length, line, col);
  return tokens;
}
