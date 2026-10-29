<script lang="ts">
    // The selections: named, reusable sets of criteria; the device table and the notification
    // rules each use one.
    import {t} from 'occulite-ui/i18n';
    import type {NoticesStore} from 'occulite-ui/notices';

    import ConfirmDialog from './ConfirmDialog.svelte';
    import SelectionDialog from './SelectionDialog.svelte';
    import {del, post, put} from './api.js';
    import {criteriaCount, emptySelection, type Config, type Selection} from './model.js';

    let {config, notices, onchanged}: {config: Config; notices: NoticesStore; onchanged: (c: Config) => void} = $props();

    let editorOpen = $state(false);
    let editing = $state<Selection | undefined>();
    let removing = $state<Selection | undefined>();

    function usedBy(s: Selection): string[] {
        const out: string[] = [];
        if (config.device_table === s.id) out.push(t('device table'));
        for (const r of config.traps.rules) if (r.selection === s.id) out.push(t('notification rule'));
        return out;
    }

    async function save(s: Selection) {
        const c = s.id ? await put<Config>(`api/v1/selections/${encodeURIComponent(s.id)}`, s) : await post<Config>('api/v1/selections', s);
        onchanged(c);
        editorOpen = false;
        notices.push('info', t('Saved.'));
    }

    function duplicate(s: Selection) {
        editing = {...structuredClone($state.snapshot(s)), id: '', name: t('{name} (copy)', {name: s.name})};
        editorOpen = true;
    }

    async function remove() {
        const s = removing;
        removing = undefined;
        if (!s) return;
        try {
            onchanged(await del<Config>(`api/v1/selections/${encodeURIComponent(s.id)}`));
            notices.push('info', t('Removed.'));
        } catch (e) {
            notices.push('error', (e as Error).message);
        }
    }
</script>

<section class="snmp-section" data-testid="selections">
    <div class="snmp-section-head">
        <h2>{t('Selections')}</h2>
        <button class="hmm-button snmp-primary" onclick={() => ((editing = emptySelection()), (editorOpen = true))} data-testid="selection-add">{t('New selection')}</button>
    </div>
    <p class="snmp-help">{t('A selection chooses devices and channels: tick them, or filter by interface, type, datapoint, room and function. The device table and the notification rules each use one; without one they take every device.')}</p>
    {#if config.selections.length === 0}
        <p class="snmp-muted">{t('No selections yet.')}</p>
    {:else}
        <table class="snmp-grid">
            <thead><tr><th>{t('Name')}</th><th>{t('Criteria')}</th><th>{t('Used by')}</th><th></th></tr></thead>
            <tbody>
                {#each config.selections as s (s.id)}
                    <tr>
                        <td>{s.name}</td>
                        <td>{criteriaCount(s) === 0 ? t('every device') : t('{n} criteria', {n: criteriaCount(s)})}{s.objects.length ? ' · ' + t('{n} ticked', {n: s.objects.length}) : ''}</td>
                        <td>{usedBy(s).join(', ') || '–'}</td>
                        <td class="snmp-cell-actions">
                            <button class="hmm-button" onclick={() => ((editing = s), (editorOpen = true))}>{t('Edit')}</button>
                            <button class="hmm-button" onclick={() => duplicate(s)}>{t('Duplicate')}</button>
                            <button class="hmm-button" onclick={() => (removing = s)} disabled={usedBy(s).length > 0} title={usedBy(s).length ? t('in use') : ''}>{t('Remove')}</button>
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    {/if}
</section>

<SelectionDialog open={editorOpen} selection={editing} onclose={() => (editorOpen = false)} onsave={save} />
<ConfirmDialog
    open={removing !== undefined}
    title={t('Remove')}
    message={t('Remove the selection {name}?', {name: removing?.name ?? ''})}
    confirmLabel={t('Remove')}
    danger
    onconfirm={remove}
    onclose={() => (removing = undefined)}
/>
