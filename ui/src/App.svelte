<script lang="ts">
    // The configuration page: the agent, who may read it, the selections, which selection fills
    // the device table, the notifications, and what the agent is doing.
    import {Notices, Tabs, ThemeSwitch} from 'occulite-ui';
    import {i18n, t} from 'occulite-ui/i18n';
    import {NoticesStore} from 'occulite-ui/notices';
    import {cycleTheme, theme} from 'occulite-ui/theme';

    import AccessTab from './AccessTab.svelte';
    import AgentTab from './AgentTab.svelte';
    import SelectionsTab from './SelectionsTab.svelte';
    import StatusTab from './StatusTab.svelte';
    import TablesTab from './TablesTab.svelte';
    import TrapsTab from './TrapsTab.svelte';
    import {get} from './api.js';
    import type {Config} from './model.js';

    const notices = new NoticesStore();
    let tab = $state('agent');
    let config = $state<Config | undefined>();
    let loadError = $state('');

    async function load() {
        try {
            config = await get<Config>('api/v1/config');
            loadError = '';
        } catch (e) {
            loadError = (e as Error).message;
        }
    }

    $effect(() => {
        load();
    });

    function changed(c: Config) {
        config = c;
    }

    const tabs = $derived([
        {id: 'agent', label: t('Agent')},
        {id: 'access', label: t('Access'), ...(config && config.users.length + config.communities.length === 0 ? {badge: '!'} : {})},
        {id: 'selections', label: t('Selections')},
        {id: 'tables', label: t('Tables')},
        ...(config?.traps_available ? [{id: 'traps', label: t('Notifications')}] : []),
        {id: 'status', label: t('Status')},
    ]);
</script>

<div class="snmp-app" lang={i18n.language}>
    <header class="snmp-header">
        <h1>SNMP</h1>
        <Tabs {tabs} bind:active={tab} label="SNMP" testId="tabs" />
        <span class="snmp-spacer"></span>
        {#if !theme.followsShell}
            <ThemeSwitch theme={theme.choice} onclick={cycleTheme} />
        {/if}
    </header>
    {#if loadError}
        <div class="snmp-banner" role="alert">{t('The page could not read the configuration: {error}', {error: loadError})}</div>
    {/if}
    <main class="snmp-page">
        {#if config}
            {#if tab === 'agent'}
                <AgentTab {config} {notices} onchanged={changed} />
            {:else if tab === 'access'}
                <AccessTab {config} {notices} onchanged={changed} />
            {:else if tab === 'selections'}
                <SelectionsTab {config} {notices} onchanged={changed} />
            {:else if tab === 'tables'}
                <TablesTab {config} {notices} onchanged={changed} />
            {:else if tab === 'traps'}
                <TrapsTab {config} {notices} onchanged={changed} />
            {:else}
                <StatusTab {config} />
            {/if}
        {:else if !loadError}
            <p class="snmp-muted">{t('Loading…')}</p>
        {/if}
    </main>
    <Notices notices={notices.visible} ondismiss={(id) => notices.dismiss(id)} />
</div>
