/**
 * Structured logger — JSON lines to stdout/stderr.
 * Mirrors the logging style used in the token-radar and contract-auditor projects.
 */

import { createWriteStream, WriteStream } from 'node:fs';
import { stdout, stderr } from 'node:process';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
};

export class Logger {
  private context: string;
  private minLevel: LogLevel;

  constructor(context: string, level: LogLevel = 'info') {
    this.context = context;
    this.minLevel = (process.env.LOG_LEVEL as LogLevel) || level;
  }

  private shouldLog(level: LogLevel): boolean {
    return LEVEL_PRIORITY[level] >= LEVEL_PRIORITY[this.minLevel];
  }

  private format(level: LogLevel, msg: string, extra?: unknown): string {
    const entry: Record<string, unknown> = {
      level,
      time: new Date().toISOString(),
      context: this.context,
      msg
    };
    if (extra !== undefined) {
      entry.extra = extra;
    }
    return JSON.stringify(entry);
  }

  debug(msg: string, extra?: unknown): void {
    if (this.shouldLog('debug')) {
      stderr.write(this.format('debug', msg, extra) + '\n');
    }
  }

  info(msg: string, extra?: unknown): void {
    if (this.shouldLog('info')) {
      stderr.write(this.format('info', msg, extra) + '\n');
    }
  }

  warn(msg: string, extra?: unknown): void {
    if (this.shouldLog('warn')) {
      stderr.write(this.format('warn', msg, extra) + '\n');
    }
  }

  error(msg: string, extra?: unknown): void {
    if (this.shouldLog('error')) {
      stderr.write(this.format('error', msg, extra) + '\n');
    }
  }
}
