#!/usr/bin/env node
// Entry point. Kept separate from cli.js so that importing the chat renderer for a
// test cannot run a command as a side effect.

import { pathToFileURL } from 'node:url';
import { main } from './cli.js';

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2));
}
