<script lang="ts">
    // Who may read the agent: SNMPv3 users (authPriv always) and, opt-in, v1/v2c communities.
    import {t} from 'occulite-ui/i18n';
    import type {NoticesStore} from 'occulite-ui/notices';

    import CommunityDialog from './CommunityDialog.svelte';
    import ConfirmDialog from './ConfirmDialog.svelte';
    import UserDialog from './UserDialog.svelte';
    import {del} from './api.js';
    import {walkCommand, walkCommandCommunity, type Community, type Config, type UserView} from './model.js';

    let {config, notices, onchanged}: {config: Config; notices: NoticesStore; onchanged: (c: Config) => void} = $props();

    let userOpen = $state(false);
    let editingUser = $state<UserView | undefined>();
    let commOpen = $state(false);
    let editingComm = $state<Community | undefined>();
    let removing = $state<{kind: 'user' | 'community'; id: string; label: string} | undefined>();

    const host = typeof location !== 'undefined' ? location.hostname : 'ccu';

    function viewLabel(v: string): string {
        return v === 'standard' ? t('The standard MIBs only') : v === 'homematic' ? t('The Homematic tree only') : t('Everything');
    }

    async function remove() {
        const r = removing;
        removing = undefined;
        if (!r) return;
        try {
            onchanged(await del<Config>(r.kind === 'user' ? `api/v1/users/${encodeURIComponent(r.id)}` : `api/v1/communities/${encodeURIComponent(r.id)}`));
            notices.push('info', t('Removed.'));
        } catch (e) {
            notices.push('error', (e as Error).message);
        }
    }
</script>

{#if config.users.length + config.communities.length === 0}
    <p class="snmp-notice" data-testid="no-credentials">{t('Nobody can read the agent yet: add an SNMPv3 user (or a community) first.')}</p>
{/if}

<section class="snmp-section" data-testid="users">
    <div class="snmp-section-head">
        <h2>{t('SNMPv3 users')}</h2>
        <button class="hmm-button snmp-primary" onclick={() => ((editingUser = undefined), (userOpen = true))} data-testid="user-add">{t('Add user')}</button>
    </div>
    {#if config.users.length === 0}
        <p class="snmp-muted">{t('No users.')}</p>
    {:else}
        <table class="snmp-grid">
            <thead><tr><th>{t('User name')}</th><th>{t('Security')}</th><th>{t('May read')}</th><th></th></tr></thead>
            <tbody>
                {#each config.users as u (u.name)}
                    <tr>
                        <td>{u.name}</td>
                        <td>authPriv · {u.auth} · {u.priv === 'AES' ? 'AES-128' : u.priv}</td>
                        <td>{viewLabel(u.view)}</td>
                        <td class="snmp-cell-actions">
                            <button class="hmm-button" onclick={() => ((editingUser = u), (userOpen = true))}>{t('Edit')}</button>
                            <button class="hmm-button" onclick={() => (removing = {kind: 'user', id: u.name, label: u.name})}>{t('Remove')}</button>
                        </td>
                    </tr>
                    <tr class="snmp-subrow"><td colspan="4"><code class="snmp-code">{walkCommand(u, host, config.port)}</code></td></tr>
                {/each}
            </tbody>
        </table>
    {/if}
</section>

<section class="snmp-section" data-testid="communities">
    <div class="snmp-section-head">
        <h2>{t('Communities (SNMPv1/v2c)')}</h2>
        <button class="hmm-button" onclick={() => ((editingComm = undefined), (commOpen = true))} data-testid="community-add">{t('Add community')}</button>
    </div>
    <p class="snmp-warning">{t('Off until you add one. Cleartext: anyone on the path can read the community.')}</p>
    {#if config.communities.length > 0}
        <table class="snmp-grid">
            <thead><tr><th>{t('Community')}</th><th>{t('Accepted from')}</th><th>{t('May read')}</th><th></th></tr></thead>
            <tbody>
                {#each config.communities as c (c.id)}
                    <tr>
                        <td><code class="snmp-code">{c.name}</code></td>
                        <td>{c.sources.length ? c.sources.join(', ') : t('nobody')}</td>
                        <td>{viewLabel(c.view)}</td>
                        <td class="snmp-cell-actions">
                            <button class="hmm-button" onclick={() => ((editingComm = c), (commOpen = true))}>{t('Edit')}</button>
                            <button class="hmm-button" onclick={() => (removing = {kind: 'community', id: c.id, label: t('this community')})}>{t('Remove')}</button>
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
        <p><code class="snmp-code">{walkCommandCommunity(host, config.port)}</code></p>
    {/if}
</section>

<UserDialog open={userOpen} {config} user={editingUser} onclose={() => (userOpen = false)} onsaved={(c) => ((userOpen = false), onchanged(c), notices.push('info', t('Saved.')))} />
<CommunityDialog open={commOpen} community={editingComm} onclose={() => (commOpen = false)} onsaved={(c) => ((commOpen = false), onchanged(c), notices.push('info', t('Saved.')))} />
<ConfirmDialog
    open={removing !== undefined}
    title={t('Remove')}
    message={t('Remove {name}? Monitoring systems that use it get no answer any more.', {name: removing?.label ?? ''})}
    confirmLabel={t('Remove')}
    danger
    onconfirm={remove}
    onclose={() => (removing = undefined)}
/>
