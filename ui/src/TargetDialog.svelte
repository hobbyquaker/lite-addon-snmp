<script lang="ts">
    // Adds or changes a notification target: a v2c trap with its community, or a v3 trap or
    // inform sent as one of the agent's users; which rules it gets.
    import {Dialog} from 'occulite-ui';
    import {t} from 'occulite-ui/i18n';

    import {RULE_KINDS, type Config, type Target} from './model.js';

    let {open, config, target, onclose, onsave}: {open: boolean; config: Config; target: Target | undefined; onclose: () => void; onsave: (t: Target) => Promise<void>} = $props();

    let draft = $state<Target>({id: '', name: '', enabled: true, host: '', port: 162, kind: 'v3-trap', rules: []});
    let error = $state('');
    let busy = $state(false);

    $effect(() => {
        if (!open) return;
        draft = target ? structuredClone($state.snapshot(target)) : {id: '', name: '', enabled: true, host: '', port: 162, kind: 'v3-trap', user: config.users[0]?.name ?? '', rules: []};
        error = '';
    });

    const valid = $derived(
        draft.name.trim() !== '' &&
            draft.host.trim() !== '' &&
            draft.port >= 1 &&
            draft.port <= 65535 &&
            (draft.kind === 'v2c-trap' ? !!draft.community : !!draft.user),
    );

    // no rule ticked off is every rule (an empty list, which also takes rules added later)
    function toggleRule(k: string) {
        const set = draft.rules.length === 0 ? [...RULE_KINDS] : [...draft.rules];
        const next = set.includes(k) ? set.filter((r) => r !== k) : [...set, k];
        draft.rules = next.length === RULE_KINDS.length ? [] : next;
    }

    async function save() {
        busy = true;
        error = '';
        try {
            await onsave($state.snapshot(draft));
        } catch (e) {
            error = (e as Error).message;
        } finally {
            busy = false;
        }
    }
</script>

<Dialog {open} title={target ? t('Notification target') : t('New notification target')} width="34rem" closable={!busy} {onclose} testId="target-dialog">
    <div class="snmp-form">
        <label for="tg-name">{t('Name')}</label>
        <input id="tg-name" class="hmm-input" type="text" bind:value={draft.name} maxlength="64" data-testid="target-name" />
        <label for="tg-host">{t('Host')}</label>
        <input id="tg-host" class="hmm-input" type="text" bind:value={draft.host} placeholder="nms.example.org" data-testid="target-host" />
        <label for="tg-port">{t('Port')}</label>
        <input id="tg-port" class="hmm-input" type="number" min="1" max="65535" bind:value={draft.port} data-testid="target-port" />
        <label for="tg-kind">{t('Kind')}</label>
        <select id="tg-kind" class="hmm-select" bind:value={draft.kind} data-testid="target-kind">
            <option value="v3-trap">{t('SNMPv3 trap')}</option>
            <option value="v3-inform">{t('SNMPv3 inform (acknowledged)')}</option>
            <option value="v2c-trap">{t('SNMPv2c trap (cleartext)')}</option>
        </select>
        {#if draft.kind === 'v2c-trap'}
            <label for="tg-com">{t('Community')}</label>
            <input id="tg-com" class="hmm-input" type="text" bind:value={draft.community} maxlength="64" autocomplete="off" data-testid="target-community" />
        {:else}
            <label for="tg-user">{t('Sent as user')}</label>
            <select id="tg-user" class="hmm-select" bind:value={draft.user} data-testid="target-user">
                {#each config.users as u (u.name)}<option value={u.name}>{u.name}</option>{/each}
            </select>
            {#if config.users.length === 0}<p class="snmp-help snmp-span">{t('Add an SNMPv3 user under Access first.')}</p>{/if}
            <p class="snmp-help snmp-span">{draft.kind === 'v3-trap' ? t('The receiver needs this user with the agent\'s engine id (Agent tab).') : t('The receiver needs this user; its own engine id is discovered.')}</p>
        {/if}
        <span class="snmp-label">{t('Gets')}</span>
        <div class="snmp-checklist">
            {#each RULE_KINDS as k (k)}
                <label class="snmp-check"><input type="checkbox" checked={draft.rules.length === 0 || draft.rules.includes(k)} onchange={() => toggleRule(k)} /> {t('rule.' + k)}</label>
            {/each}
        </div>
        <label class="snmp-check"><input type="checkbox" bind:checked={draft.enabled} /> {t('Enabled')}</label>
    </div>
    <p class="snmp-error" role="alert">{error}</p>
    {#snippet buttons()}
        <button class="hmm-button" onclick={onclose} disabled={busy}>{t('Cancel')}</button>
        <button class="hmm-button snmp-primary" onclick={save} disabled={!valid || busy} data-testid="target-save">{t('Save')}</button>
    {/snippet}
</Dialog>
