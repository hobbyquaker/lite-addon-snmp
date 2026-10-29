<script lang="ts">
    // The notifications: the rules (what raises one, for which devices) and the targets (where
    // they go, as what), each target with a test.
    import {t} from 'occulite-ui/i18n';
    import type {NoticesStore} from 'occulite-ui/notices';

    import ConfirmDialog from './ConfirmDialog.svelte';
    import TargetDialog from './TargetDialog.svelte';
    import {post, put} from './api.js';
    import {DEVICE_RULES, RULE_KINDS, type Config, type Rule, type Target, type Traps} from './model.js';

    let {config, notices, onchanged}: {config: Config; notices: NoticesStore; onchanged: (c: Config) => void} = $props();

    let dialogOpen = $state(false);
    let editing = $state<Target | undefined>();
    let removing = $state<Target | undefined>();
    let testing = $state('');

    function rule(kind: string): Rule {
        return config.traps.rules.find((r) => r.kind === kind) ?? {kind, enabled: false, selection: ''};
    }

    async function saveTraps(tr: Traps) {
        onchanged(await put<Config>('api/v1/traps', tr));
    }

    async function setRule(kind: string, patch: Partial<Rule>) {
        const rules = RULE_KINDS.map((k) => (k === kind ? {...rule(k), ...patch} : rule(k)));
        try {
            await saveTraps({targets: $state.snapshot(config.traps.targets), rules});
        } catch (e) {
            notices.push('error', (e as Error).message);
        }
    }

    async function saveTarget(tg: Target) {
        const targets = $state.snapshot(config.traps.targets).filter((x) => x.id !== tg.id || tg.id === '');
        const i = config.traps.targets.findIndex((x) => x.id === tg.id && tg.id !== '');
        if (i >= 0) targets.splice(i, 0, tg);
        else targets.push(tg);
        await saveTraps({targets, rules: $state.snapshot(config.traps.rules)});
        dialogOpen = false;
        notices.push('info', t('Saved.'));
    }

    async function remove() {
        const tg = removing;
        removing = undefined;
        if (!tg) return;
        try {
            await saveTraps({targets: $state.snapshot(config.traps.targets).filter((x) => x.id !== tg.id), rules: $state.snapshot(config.traps.rules)});
        } catch (e) {
            notices.push('error', (e as Error).message);
        }
    }

    async function test(tg: Target) {
        testing = tg.id;
        try {
            await post(`api/v1/traps/targets/${encodeURIComponent(tg.id)}/test`);
            notices.push('info', tg.kind === 'v3-inform' ? t('The test was acknowledged.') : t('The test was sent.'));
        } catch (e) {
            notices.push('error', (e as Error).message);
        } finally {
            testing = '';
        }
    }

    async function setAuthTraps(on: boolean) {
        try {
            onchanged(await put<Config>('api/v1/agent', {auth_traps: on}));
        } catch (e) {
            notices.push('error', (e as Error).message);
        }
    }
</script>

<section class="snmp-section" data-testid="rules">
    <h2>{t('Rules')}</h2>
    <p class="snmp-help">{t('Each rule raises a notification when something comes up and another when it goes away. After a restart the present state is the baseline: only changes are sent.')}</p>
    <table class="snmp-grid">
        <thead><tr><th>{t('Rule')}</th><th>{t('Devices')}</th><th></th></tr></thead>
        <tbody>
            {#each RULE_KINDS as k (k)}
                {@const r = rule(k)}
                <tr>
                    <td><label class="snmp-check"><input type="checkbox" checked={r.enabled} onchange={(e) => setRule(k, {enabled: (e.target as HTMLInputElement).checked})} data-testid={'rule-' + k} /> {t('rule.' + k)}</label></td>
                    <td>
                        {#if DEVICE_RULES.includes(k)}
                            <select class="hmm-select" value={r.selection} onchange={(e) => setRule(k, {selection: (e.target as HTMLSelectElement).value})} aria-label={t('Selection')}>
                                <option value="">{t('Every device')}</option>
                                {#each config.selections as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
                            </select>
                        {:else if k === 'duty-cycle'}
                            <label class="snmp-check">{t('Threshold')}
                                <input class="hmm-input snmp-narrow" type="number" min="0" max="100" value={r.threshold ?? 0} onchange={(e) => setRule(k, {threshold: Number((e.target as HTMLInputElement).value)})} /> %
                            </label>
                            <span class="snmp-muted">{t('0: the interface\'s own threshold')}</span>
                        {:else}
                            –
                        {/if}
                    </td>
                    <td class="snmp-muted">{t('ruleinfo.' + k)}</td>
                </tr>
            {/each}
        </tbody>
    </table>
    <label class="snmp-check"><input type="checkbox" checked={config.auth_traps} onchange={(e) => setAuthTraps((e.target as HTMLInputElement).checked)} /> {t('authenticationFailure on a wrong community or password (at most once a minute)')}</label>
</section>

<section class="snmp-section" data-testid="targets">
    <div class="snmp-section-head">
        <h2>{t('Targets')}</h2>
        <button class="hmm-button snmp-primary" onclick={() => ((editing = undefined), (dialogOpen = true))} data-testid="target-add">{t('Add target')}</button>
    </div>
    <p class="snmp-help">{t('Each target gets at most 20 notifications a minute; a queue of 1,000 per target keeps the rest while it does not answer. coldStart goes to every target when the agent starts.')}</p>
    {#if config.traps.targets.length === 0}
        <p class="snmp-muted">{t('No targets: no notification leaves the system.')}</p>
    {:else}
        <table class="snmp-grid">
            <thead><tr><th>{t('Name')}</th><th>{t('Receiver')}</th><th>{t('Kind')}</th><th>{t('Gets')}</th><th></th></tr></thead>
            <tbody>
                {#each config.traps.targets as tg (tg.id)}
                    <tr>
                        <td><span class="snmp-pill" class:ok={tg.enabled}>{tg.enabled ? t('on') : t('off')}</span> {tg.name}</td>
                        <td><code class="snmp-code">{tg.host}:{tg.port}</code></td>
                        <td>{tg.kind === 'v2c-trap' ? 'v2c trap' : tg.kind === 'v3-trap' ? 'v3 trap · ' + tg.user : 'v3 inform · ' + tg.user}</td>
                        <td>{tg.rules.length === 0 ? t('all rules') : tg.rules.map((r) => t('rule.' + r)).join(', ')}</td>
                        <td class="snmp-cell-actions">
                            <button class="hmm-button snmp-fixed" onclick={() => test(tg)} disabled={testing !== ''} data-testid={'target-test-' + tg.name}>{testing === tg.id ? t('Sending…') : t('Test')}</button>
                            <button class="hmm-button" onclick={() => ((editing = tg), (dialogOpen = true))}>{t('Edit')}</button>
                            <button class="hmm-button" onclick={() => (removing = tg)}>{t('Remove')}</button>
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    {/if}
</section>

<TargetDialog open={dialogOpen} {config} target={editing} onclose={() => (dialogOpen = false)} onsave={saveTarget} />
<ConfirmDialog
    open={removing !== undefined}
    title={t('Remove')}
    message={t('Remove the target {name}?', {name: removing?.name ?? ''})}
    confirmLabel={t('Remove')}
    danger
    onconfirm={remove}
    onclose={() => (removing = undefined)}
/>
