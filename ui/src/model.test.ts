import {describe, expect, it} from 'vitest';

import {criteriaCount, emptySelection, formatValue, normaliseSelection, parseSources, ruleCount, walkCommand} from './model.js';

describe('selection helpers', () => {
    it('counts criteria', () => {
        expect(criteriaCount(emptySelection())).toBe(0);
        expect(criteriaCount({...emptySelection(), rooms: ['Bad'], keys: ['LOW*']})).toBe(2);
    });
    it('normalises a partial selection', () => {
        const s = normaliseSelection({name: 'x', rooms: ['Bad']});
        expect(s.keys).toEqual([]);
        expect(s.rooms).toEqual(['Bad']);
        expect(s.log_priority).toBe('');
    });
    it('counts rules as the forwarder does', () => {
        expect(ruleCount({...emptySelection(), rooms: ['Bad', 'Flur'], keys: ['LOW*']})).toBe(3);
        expect(formatValue(2.91234)).toBe('2.912');
    });
});

describe('the walk hint', () => {
    it('never carries a password', () => {
        const c = walkCommand({name: 'nms', auth: 'SHA-256', priv: 'AES', view: 'all'}, 'ccu', 161);
        expect(c).toContain('-u nms');
        expect(c).toContain('-a SHA-256');
        expect(c).toContain("-A '<auth password>'");
        expect(c).not.toContain(':161');
    });
    it('splits sources', () => {
        expect(parseSources('local, 192.168.1.0/24\n10.0.0.5')).toEqual(['local', '192.168.1.0/24', '10.0.0.5']);
    });
});
