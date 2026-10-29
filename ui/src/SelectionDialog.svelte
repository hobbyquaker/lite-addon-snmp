<script lang="ts">
    // The dialog around the selection editor (lite-addon-forwarder's, see SelectionEditor.svelte):
    // the editor with the agent's inventory and live count, and under it the first devices that
    // match - the rows the device table would get.
    import {Dialog} from 'occulite-ui';
    import {t} from 'occulite-ui/i18n';

    import SelectionEditor from './SelectionEditor.svelte';
    import {get, post} from './api.js';
    import {normaliseSelection, type Inventory, type Match, type Preview, type Selection} from './model.js';

    let {open, selection, onclose, onsave}: {open: boolean; selection: Selection | undefined; onclose: () => void; onsave: (s: Selection) => Promise<void>} = $props();

    let draft = $state<Selection>(normaliseSelection({}));
    let inventory = $state<Inventory | undefined>();
    let preview = $state<Preview | undefined>();
    let busy = $state(false);
    let error = $state('');

    $effect(() => {
        if (!open) return;
        draft = normaliseSelection(structuredClone($state.snapshot(selection) ?? {name: ''}));
        error = '';
        preview = undefined;
        get<Inventory>('api/v1/catalog')
            .then((c) => (inventory = c))
            .catch((e) => (error = (e as Error).message));
    });

    async function onmatch(s: Selection): Promise<Match> {
        const p = await post<Preview>('api/v1/selections/preview', {...s, name: s.name || 'preview'});
        preview = p;
        return p;
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

<Dialog {open} title={selection?.id ? t('Edit selection') : t('New selection')} width="64rem" height="88vh" minWidth={720} closable={!busy} {onclose} testId="selection-editor">
    {#if open}
        <div class="snmp-editor">
            <SelectionEditor bind:value={draft} {inventory} {onmatch} devicesOnly showRecent={false} />
            <div class="snmp-preview" data-testid="selection-preview">
                <span class="snmp-count" data-testid="selection-count" aria-live="polite">
                    {#if preview}{t('{devices} devices, {channels} channels, {datapoints} datapoints match', {devices: preview.count.devices, channels: preview.count.channels, datapoints: preview.count.datapoints})}{:else}&nbsp;{/if}
                </span>
                {#if preview}
                    <table class="snmp-grid snmp-grid-compact">
                        <thead><tr><th>{t('Device')}</th><th>{t('Type')}</th><th>{t('Interface')}</th><th>{t('Rooms')}</th><th>{t('Channels')}</th></tr></thead>
                        <tbody>
                            {#each preview.sample as r (r.interface + r.address)}
                                <tr><td>{r.name || r.address}</td><td>{r.type}</td><td>{r.interface}</td><td>{r.rooms.join(', ')}</td><td>{r.channels}</td></tr>
                            {:else}
                                <tr><td colspan="5" class="snmp-muted">{t('Nothing matches.')}</td></tr>
                            {/each}
                        </tbody>
                    </table>
                    {#if preview.count.devices > preview.sample.length}<p class="snmp-muted">{t('The first {n} of {total}.', {n: preview.sample.length, total: preview.count.devices})}</p>{/if}
                {/if}
            </div>
        </div>
    {/if}
    <p class="snmp-error" role="alert">{error}</p>
    {#snippet buttons()}
        <button class="hmm-button" onclick={onclose} disabled={busy}>{t('Cancel')}</button>
        <button class="hmm-button snmp-primary" onclick={save} disabled={busy || draft.name.trim() === ''} data-testid="selection-save">{t('Save')}</button>
    {/snippet}
</Dialog>
