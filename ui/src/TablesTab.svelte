<script lang="ts">
    // Which selection fills the device table, and the rows the agent serves with their index.
    import {t} from 'occulite-ui/i18n';
    import type {NoticesStore} from 'occulite-ui/notices';

    import {get, put} from './api.js';
    import type {Config} from './model.js';

    let {config, notices, onchanged}: {config: Config; notices: NoticesStore; onchanged: (c: Config) => void} = $props();

    interface Rows {
        column_prefix: string;
        rows: {interface: string; address: string; type: string; name: string; index: string}[];
    }

    let rows = $state<Rows | undefined>();
    let busy = $state(false);

    async function loadRows() {
        try {
            rows = await get<Rows>('api/v1/tables/devices');
        } catch (e) {
            notices.push('error', (e as Error).message);
        }
    }

    $effect(() => {
        void config.device_table;
        loadRows();
    });

    async function setTable(id: string) {
        busy = true;
        try {
            onchanged(await put<Config>('api/v1/tables', {device_table: id}));
            setTimeout(loadRows, 2100);
        } catch (e) {
            notices.push('error', (e as Error).message);
        } finally {
            busy = false;
        }
    }
</script>

<section class="snmp-section" data-testid="tables">
    <h2>{t('Device table (hmDeviceTable)')}</h2>
    <div class="snmp-form">
        <label for="dev-sel">{t('Rows')}</label>
        <select class="hmm-select" id="dev-sel" value={config.device_table} onchange={(e) => setTable((e.target as HTMLSelectElement).value)} disabled={busy} data-testid="device-table-selection">
            <option value="">{t('Every device')}</option>
            {#each config.selections as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
        </select>
    </div>
    <p class="snmp-help">{t('Each row is indexed by the interface and the address as strings, so a device keeps its OID across restarts and re-pairing.')}</p>
    {#if rows}
        <p class="snmp-muted" data-testid="device-rows-count">{t('{n} rows', {n: rows.rows.length})} · {t('column prefix')} <code class="snmp-code">{rows.column_prefix}</code></p>
        <div class="snmp-scroll">
            <table class="snmp-grid snmp-grid-compact">
                <thead><tr><th>{t('Device')}</th><th>{t('Type')}</th><th>{t('Interface')}</th><th>{t('Index')}</th></tr></thead>
                <tbody>
                    {#each rows.rows as r (r.index)}
                        <tr><td>{r.name || r.address}</td><td>{r.type}</td><td>{r.interface}</td><td><code class="snmp-code">{r.index}</code></td></tr>
                    {/each}
                </tbody>
            </table>
        </div>
    {/if}
</section>
<section class="snmp-section">
    <h2>{t('Datapoint table')}</h2>
    <p class="snmp-muted">{t('A table of selected datapoints and their values follows in a later version.')}</p>
</section>
