<script lang="ts">
    // Adds or changes an SNMPv1/v2c community: cleartext on the wire, so it is accepted only from
    // the sources listed (local networks by default).
    import {Dialog} from 'occulite-ui';
    import {t} from 'occulite-ui/i18n';

    import {post, put} from './api.js';
    import {parseSources, type Community, type Config, type View} from './model.js';

    let {open, community, onclose, onsaved}: {open: boolean; community: Community | undefined; onclose: () => void; onsaved: (c: Config) => void} = $props();

    let name = $state('');
    let view = $state<View>('all');
    let sources = $state('local');
    let error = $state('');
    let busy = $state(false);

    $effect(() => {
        if (!open) return;
        name = community?.name ?? '';
        view = community?.view ?? 'all';
        sources = (community?.sources ?? ['local']).join(', ');
        error = '';
    });

    const isNew = $derived(community === undefined);
    const valid = $derived(name.length >= 1 && name.length <= 64);

    async function save() {
        busy = true;
        error = '';
        try {
            const body = {name, view, sources: parseSources(sources)};
            const c = isNew ? await post<Config>('api/v1/communities', body) : await put<Config>(`api/v1/communities/${encodeURIComponent(community!.id)}`, body);
            onsaved(c);
        } catch (e) {
            error = (e as Error).message;
        } finally {
            busy = false;
        }
    }
</script>

<Dialog {open} title={isNew ? t('New community') : t('Community')} width="32rem" closable={!busy} {onclose} testId="community-dialog">
    <p class="snmp-warning">{t('SNMPv1 and v2c send the community in cleartext: anyone on the path can read it. Prefer an SNMPv3 user.')}</p>
    <div class="snmp-form">
        <label for="c-name">{t('Community')}</label>
        <input class="hmm-input" id="c-name" type="text" bind:value={name} maxlength="64" autocomplete="off" data-testid="community-name" />
        <label for="c-view">{t('May read')}</label>
        <select class="hmm-select" id="c-view" bind:value={view}>
            <option value="all">{t('Everything')}</option>
            <option value="standard">{t('The standard MIBs only')}</option>
            <option value="homematic">{t('The Homematic tree only')}</option>
        </select>
        <label for="c-src">{t('Accepted from')}</label>
        <textarea class="hmm-input" id="c-src" rows="2" bind:value={sources} data-testid="community-sources"></textarea>
        <p class="snmp-help snmp-span">{t('Addresses or networks (192.168.1.0/24), separated by commas; "local" stands for the private and link-local networks. Empty accepts nobody.')}</p>
    </div>
    <p class="snmp-error" role="alert">{error}</p>
    {#snippet buttons()}
        <button class="hmm-button" onclick={onclose} disabled={busy}>{t('Cancel')}</button>
        <button class="hmm-button snmp-primary" onclick={save} disabled={!valid || busy} data-testid="community-save">{t('Save')}</button>
    {/snippet}
</Dialog>
