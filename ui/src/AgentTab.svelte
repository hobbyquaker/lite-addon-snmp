<script lang="ts">
    // The agent's switches and the system group's strings, the engine id and the MIB download.
    import {copyText} from 'occulite-ui';
    import {t} from 'occulite-ui/i18n';
    import type {NoticesStore} from 'occulite-ui/notices';

    import {put} from './api.js';
    import type {Config} from './model.js';

    let {config, notices, onchanged}: {config: Config; notices: NoticesStore; onchanged: (c: Config) => void} = $props();

    let form = $state({enabled: true, sys_name: '', sys_location: '', sys_contact: '', ipv4: true, ipv6: true, lang: 'de'});
    let busy = $state(false);

    $effect(() => {
        form = {enabled: config.enabled, sys_name: config.sys_name, sys_location: config.sys_location, sys_contact: config.sys_contact, ipv4: config.ipv4, ipv6: config.ipv6, lang: config.lang};
    });

    const dirty = $derived(
        form.enabled !== config.enabled ||
            form.sys_name !== config.sys_name ||
            form.sys_location !== config.sys_location ||
            form.sys_contact !== config.sys_contact ||
            form.ipv4 !== config.ipv4 ||
            form.ipv6 !== config.ipv6 ||
            form.lang !== config.lang,
    );

    async function save() {
        busy = true;
        try {
            onchanged(await put<Config>('api/v1/agent', form));
            notices.push('info', t('Saved.'));
        } catch (e) {
            notices.push('error', (e as Error).message);
        } finally {
            busy = false;
        }
    }

    async function copyEngine() {
        await copyText(config.engine_id);
        notices.push('info', t('Copied.'));
    }
</script>

<section class="snmp-section" data-testid="agent">
    <h2>{t('Agent')}</h2>
    <div class="snmp-form">
        <label class="snmp-check"><input type="checkbox" bind:checked={form.enabled} data-testid="agent-enabled" /> {t('Answer SNMP requests')}</label>
        <p class="snmp-help">{t('Read-only: the agent refuses every write. It answers nobody until a user or a community exists (Access).')}</p>

        <label for="sysname">{t('System name (sysName)')}</label>
        <input class="hmm-input" id="sysname" type="text" maxlength="255" bind:value={form.sys_name} placeholder={config.hostname} />
        <label for="sysloc">{t('Location (sysLocation)')}</label>
        <input class="hmm-input" id="sysloc" type="text" maxlength="255" bind:value={form.sys_location} />
        <label for="syscon">{t('Contact (sysContact)')}</label>
        <input class="hmm-input" id="syscon" type="text" maxlength="255" bind:value={form.sys_contact} />

        <span class="snmp-label">{t('Listen on')}</span>
        <div class="snmp-row">
            <label class="snmp-check"><input type="checkbox" bind:checked={form.ipv4} /> IPv4</label>
            <label class="snmp-check"><input type="checkbox" bind:checked={form.ipv6} /> IPv6</label>
            <span class="snmp-muted">UDP {config.port}</span>
        </div>

        <label for="lang">{t('Language of room and function names')}</label>
        <select class="hmm-select" id="lang" bind:value={form.lang}>
            <option value="de">Deutsch</option>
            <option value="en">English</option>
        </select>
    </div>
    <div class="snmp-actions">
        <button class="hmm-button snmp-primary" disabled={!dirty || busy || (!form.ipv4 && !form.ipv6)} onclick={save} data-testid="agent-save">{t('Save')}</button>
    </div>
</section>

<section class="snmp-section">
    <h2>{t('Firewall')}</h2>
    <p>{t('UDP port {port} is closed in the system firewall until you open it: Addons → SNMP → Addon ports. Opened, it is reachable from everywhere; narrow the rule to your monitoring system on the Firewall page.', {port: config.port})}</p>
    <p><a href="/addons" target="_top">{t('Open the Addons page')}</a> · <a href="/system/firewall" target="_top">{t('Open the Firewall page')}</a></p>
</section>

<section class="snmp-section">
    <h2>{t('Engine and MIB')}</h2>
    <div class="snmp-form">
        <span class="snmp-label">snmpEngineID</span>
        <div class="snmp-row">
            <code class="snmp-code" data-testid="engine-id">{config.engine_id}</code>
            <button class="hmm-button" onclick={copyEngine}>{t('Copy')}</button>
        </div>
        <span class="snmp-label">snmpEngineBoots</span>
        <span>{config.engine_boots}</span>
        <span class="snmp-label">{t('Root of the Homematic tree')}</span>
        <code class="snmp-code">{config.root}</code>
    </div>
    <p class="snmp-notice">{t('Provisional: the Homematic tree lives under net-snmp\'s experimental area until it moves to an own enterprise number. Its OIDs will change then; the release notes will say when to replace the MIB in your monitoring system.')}</p>
    <p><a href="api/v1/mib" download="LITE-SNMP-MIB.txt" data-testid="mib-download">{t('Download LITE-SNMP-MIB')}</a></p>
</section>
