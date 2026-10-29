// The API's shapes and the page's pure helpers (tested in model.test.ts).

export type View = 'all' | 'standard' | 'homematic';

export interface UserView {
    name: string;
    auth: string;
    priv: string;
    view: View;
}

export interface Community {
    id: string;
    name: string;
    view: View;
    sources: string[];
}

/** A selection, the same JSON as lite-addon-forwarder's. */
export interface Selection {
    id: string;
    name: string;
    kinds: Kind[];
    interfaces: string[];
    device_types: string[];
    channel_types: string[];
    objects: string[];
    exclude_objects: string[];
    keys: string[];
    exclude_keys: string[];
    rooms: string[];
    functions: string[];
    sources: string[];
    metric_groups: string[];
    log_streams: string[];
    log_units: string[];
    log_priority: string;
}

export interface Rule {
    kind: string;
    enabled: boolean;
    selection: string;
    threshold?: number;
}

export interface Target {
    id: string;
    name: string;
    enabled: boolean;
    host: string;
    port: number;
    kind: 'v2c-trap' | 'v3-trap' | 'v3-inform';
    community?: string;
    user?: string;
    rules: string[];
}

export interface Traps {
    targets: Target[];
    rules: Rule[];
}

export interface Config {
    enabled: boolean;
    sys_name: string;
    hostname: string;
    sys_location: string;
    sys_contact: string;
    ipv4: boolean;
    ipv6: boolean;
    lang: 'de' | 'en';
    users: UserView[];
    communities: Community[];
    selections: Selection[];
    device_table: string;
    auth_traps: boolean;
    traps: Traps;
    engine_id: string;
    engine_boots: number;
    root: string;
    port: number;
    auths: string[];
    privs: string[];
    min_password: number;
    traps_available: boolean;
}

// The editor's types, as lite-addon-forwarder's model.ts (commit 5c506f7) has them.
export type Kind = 'event' | 'metric' | 'log';

export interface ChannelInfo {
    address: string;
    index: number;
    type: string;
    name: string;
    rooms: string[];
    functions: string[];
    keys: string[];
}

export interface DeviceInfo {
    interface: string;
    address: string;
    type: string;
    name: string;
    rooms: string[];
    functions: string[];
    channels: ChannelInfo[];
}

export interface Counted {
    name: string;
    count: number;
}

export interface Inventory {
    interfaces: {name: string; protocol: string; running: boolean; devices: number}[];
    devices: DeviceInfo[];
    rooms: string[];
    functions: string[];
    device_types: Counted[];
    channel_types: Counted[];
    keys: Counted[];
    datapoints: number;
    updated_at: string;
}

/** A record of the forwarder's preview; the agent's preview answers none. */
export interface Rec {
    ts: string;
    kind: Kind;
    address?: string;
    key?: string;
    value: unknown;
    unit?: string;
    channel_name?: string;
    rooms: string[];
    summary: string;
}

export interface Match {
    count: Count;
    recent: Rec[];
}

export interface Count {
    devices: number;
    channels: number;
    datapoints: number;
}

export interface PreviewRow {
    interface: string;
    address: string;
    type: string;
    name: string;
    rooms: string[];
    channels: number;
}

/** The agent's preview: the count, the editor's (empty) records, the first matching devices. */
export interface Preview extends Match {
    sample: PreviewRow[];
}

export interface RequestInfo {
    at: string;
    source: string;
    version: string;
    credential: string;
    pdu: string;
}

export interface Status {
    listening: boolean;
    listen_error: string;
    has_credentials: boolean;
    requests_minute: number;
    requests: number;
    auth_failures: number;
    sets_refused: number;
    rate_limited: number;
    recent: RequestInfo[];
    source: {
        ready: boolean;
        stream_connected: boolean;
        system_ready: boolean;
        system_age_s: number;
        meta_revision: number;
        devices: number;
        interfaces: number;
        service_messages: number;
        reconnects: number;
        resyncs: number;
        health: number;
    };
    traps?: TrapStatus;
}

export interface TargetStatus {
    id: string;
    name: string;
    sent: number;
    failed: number;
    dropped: number;
    queued: number;
    last_error: string;
    last_sent: string;
}

export interface TrapStatus {
    sent: number;
    failed: number;
    targets: TargetStatus[];
    recent: {at: string; name: string; text: string}[];
}

/** An empty selection: matches every device. */
export function emptySelection(name = ''): Selection {
    return {
        id: '',
        name,
        kinds: [],
        interfaces: [],
        device_types: [],
        channel_types: [],
        objects: [],
        exclude_objects: [],
        keys: [],
        exclude_keys: [],
        rooms: [],
        functions: [],
        sources: [],
        metric_groups: [],
        log_streams: [],
        log_units: [],
        log_priority: '',
    };
}

/** A copy with every list present, for a selection that came from an older or foreign file. */
export function normaliseSelection(s: Partial<Selection>): Selection {
    const e = emptySelection();
    const out = {...e, ...s} as Selection;
    for (const k of Object.keys(e) as (keyof Selection)[]) {
        if (Array.isArray(e[k]) && !Array.isArray(out[k])) (out as unknown as Record<string, unknown>)[k] = [];
    }
    return out;
}

/** How many criteria a selection sets (0: every device). */
export function criteriaCount(s: Selection): number {
    return [s.interfaces, s.device_types, s.channel_types, s.objects, s.keys, s.rooms, s.functions, s.exclude_objects, s.exclude_keys].filter((l) => l.length > 0).length;
}

/** The snmpwalk line for a user, without its passwords. */
export function walkCommand(u: UserView, host: string, port: number): string {
    const auth = u.auth === 'SHA' ? 'SHA' : u.auth;
    const priv = u.priv;
    const p = port && port !== 161 ? `:${port}` : '';
    return `snmpwalk -v3 -l authPriv -u ${u.name} -a ${auth} -A '<auth password>' -x ${priv} -X '<priv password>' ${host}${p} .1.3.6.1.2.1.1`;
}

/** The same for a community. */
export function walkCommandCommunity(host: string, port: number): string {
    const p = port && port !== 161 ? `:${port}` : '';
    return `snmpwalk -v2c -c '<community>' ${host}${p} .1.3.6.1.2.1.1`;
}

/** Splits a source list typed with commas, spaces or new lines. */
export function parseSources(text: string): string[] {
    return text
        .split(/[\s,;]+/)
        .map((s) => s.trim())
        .filter((s) => s !== '');
}

/** Seconds as "3 s", "4 min", "2 h". */
export function age(s: number): string {
    if (s < 0) return '–';
    if (s < 120) return `${s} s`;
    if (s < 7200) return `${Math.round(s / 60)} min`;
    return `${Math.round(s / 3600)} h`;
}

/** The parts of a selection that are rules, with how many entries each has (lite-addon-forwarder 5c506f7). */
export function ruleCount(s: Selection): number {
    return (
        s.interfaces.length +
        s.device_types.length +
        s.channel_types.length +
        s.keys.length +
        s.exclude_keys.length +
        s.rooms.length +
        s.functions.length +
        s.metric_groups.length +
        s.log_streams.length +
        s.log_units.length +
        (s.log_priority ? 1 : 0)
    );
}

/** Formats a value for a table cell (lite-addon-forwarder 5c506f7). */
export function formatValue(v: unknown): string {
    if (v === null || v === undefined) return '';
    if (typeof v === 'number') return Number.isInteger(v) ? String(v) : String(Math.round(v * 1000) / 1000);
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'string') return v;
    return JSON.stringify(v);
}

/** The notification rules, in the page's order. */
export const RULE_KINDS = ['service-message', 'interface', 'duty-cycle', 'service', 'warning', 'unreachable'];

/** The rules that watch devices and take a selection. */
export const DEVICE_RULES = ['service-message', 'unreachable'];
