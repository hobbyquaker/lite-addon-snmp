<script lang="ts">
    // What the agent is doing: requests, the last sources, its view of the system, the notifications.
    import {t} from 'occulite-ui/i18n';

    import {get} from './api.js';
    import {age, type Config, type Status} from './model.js';

    let {config}: {config: Config} = $props();
    let status = $state<Status | undefined>();
    let error = $state('');

    async function load() {
        try {
            status = await get<Status>('api/v1/status');
            error = '';
        } catch (e) {
            error = (e as Error).message;
        }
    }

    $effect(() => {
        load();
        const id = setInterval(load, 5000);
        return () => clearInterval(id);
    });

    function health(h: number): string {
        return h === 1 ? t('ok') : h === 2 ? t('degraded') : t('unknown');
    }
</script>

{#if error}<p class="snmp-error">{error}</p>{/if}
{#if status}
    <section class="snmp-section" data-testid="status">
        <h2>{t('Agent')}</h2>
        <div class="snmp-kv">
            <span>{t('Listening')}</span>
            <span><span class="snmp-pill" class:ok={status.listening} class:bad={!status.listening && config.enabled}>{status.listening ? t('yes') : config.enabled ? t('no') : t('off')}</span> {status.listen_error}</span>
            <span>{t('Credentials')}</span>
            <span><span class="snmp-pill" class:ok={status.has_credentials} class:bad={!status.has_credentials}>{status.has_credentials ? t('yes') : t('none')}</span></span>
            <span>{t('Requests in the last minute')}</span>
            <span data-testid="requests-minute">{status.requests_minute}</span>
            <span>{t('Requests since the start')}</span>
            <span>{status.requests}</span>
            <span>{t('Authentication failures')}</span>
            <span>{status.auth_failures}</span>
            <span>{t('Refused writes')}</span>
            <span>{status.sets_refused}</span>
            <span>{t('Rate limited')}</span>
            <span>{status.rate_limited}</span>
        </div>
        <h3>{t('Last requests')}</h3>
        {#if status.recent.length === 0}
            <p class="snmp-muted">{t('None yet.')}</p>
        {:else}
            <table class="snmp-grid snmp-grid-compact">
                <thead><tr><th>{t('Time')}</th><th>{t('Source')}</th><th>{t('Version')}</th><th>{t('Credential')}</th><th>{t('Request')}</th></tr></thead>
                <tbody>
                    {#each status.recent as r (r.at + r.source + r.credential)}
                        <tr><td>{new Date(r.at).toLocaleTimeString()}</td><td>{r.source}</td><td>{r.version}</td><td>{r.version === 'v3' ? r.credential : '••••'}</td><td>{r.pdu}</td></tr>
                    {/each}
                </tbody>
            </table>
        {/if}
    </section>
    <section class="snmp-section">
        <h2>{t('System')}</h2>
        <div class="snmp-kv">
            <span>{t('Health (hmSysHealth)')}</span>
            <span><span class="snmp-pill" class:ok={status.source.health === 1} class:bad={status.source.health === 2}>{health(status.source.health)}</span></span>
            <span>{t('Event stream')}</span>
            <span><span class="snmp-pill" class:ok={status.source.stream_connected} class:bad={!status.source.stream_connected}>{status.source.stream_connected ? t('connected') : t('not connected')}</span></span>
            <span>{t('System data age')}</span>
            <span>{age(status.source.system_age_s)}</span>
            <span>{t('Metadata revision')}</span>
            <span>{status.source.meta_revision}</span>
            <span>{t('Interfaces / devices')}</span>
            <span>{status.source.interfaces} / {status.source.devices}</span>
            <span>{t('Service messages')}</span>
            <span>{status.source.service_messages}</span>
            <span>{t('Reconnects / resyncs')}</span>
            <span>{status.source.reconnects} / {status.source.resyncs}</span>
        </div>
    </section>
    {#if status.traps}
        <section class="snmp-section" data-testid="trap-status">
            <h2>{t('Notifications')}</h2>
            <div class="snmp-kv">
                <span>{t('Sent')}</span><span>{status.traps.sent}</span>
                <span>{t('Failed or dropped')}</span><span>{status.traps.failed}</span>
            </div>
            {#if status.traps.targets.length}
                <table class="snmp-grid snmp-grid-compact">
                    <thead><tr><th>{t('Target')}</th><th>{t('Sent')}</th><th>{t('Failed')}</th><th>{t('Dropped')}</th><th>{t('Queued')}</th><th>{t('Last error')}</th></tr></thead>
                    <tbody>
                        {#each status.traps.targets as tg (tg.id)}
                            <tr><td>{tg.name}</td><td>{tg.sent}</td><td>{tg.failed}</td><td>{tg.dropped}</td><td>{tg.queued}</td><td>{tg.last_error || '–'}</td></tr>
                        {/each}
                    </tbody>
                </table>
            {/if}
            {#if status.traps.recent.length}
                <h3>{t('Last notifications')}</h3>
                <ul class="snmp-list">
                    {#each status.traps.recent as n (n.at + n.name + n.text)}<li><span class="snmp-muted">{new Date(n.at).toLocaleTimeString()}</span> {n.name} {n.text}</li>{/each}
                </ul>
            {/if}
        </section>
    {/if}
{:else if !error}
    <p class="snmp-muted">{t('Loading…')}</p>
{/if}
