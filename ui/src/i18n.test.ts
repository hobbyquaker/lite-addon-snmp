import {readdirSync, readFileSync} from 'node:fs';
import {describe, expect, it} from 'vitest';

import {MESSAGES} from './messages.js';
import {RULE_KINDS} from './model.js';

// every t('…') of the page has its German and English text
describe('messages', () => {
    it('covers every key', () => {
        const dir = process.cwd() + '/src/';
        const missing: string[] = [];
        for (const f of readdirSync(dir).filter((f) => f.endsWith('.svelte'))) {
            const src = readFileSync(dir + f, 'utf8');
            for (const m of src.matchAll(/\bt\('((?:[^'\\]|\\.)*)'/g)) {
                const key = m[1]!.replace(/\\'/g, "'");
                if (key.endsWith('.')) continue; // a prefix of keys built at run time (source.event, rule.…)
                const e = MESSAGES[key] as {de?: string; en?: string} | undefined;
                if (!e?.de || !e?.en) missing.push(`${f}: ${key}`);
            }
        }
        for (const k of RULE_KINDS) for (const p of ['rule.', 'ruleinfo.']) if (!MESSAGES[p + k]) missing.push(p + k);
        expect(missing).toEqual([]);
    });
    it('never says "box"', () => {
        for (const [k, v] of Object.entries(MESSAGES)) {
            const e = v as {de: string; en: string};
            expect(`${k} ${e.de} ${e.en}`).not.toMatch(/\bbox\b/i);
        }
    });
});
