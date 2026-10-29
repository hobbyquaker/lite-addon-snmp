<script lang="ts">
    // Adds an SNMPv3 user or changes one: the passwords are write-only and never shown again; a
    // new authentication protocol needs both passwords, as the keys are derived with its hash.
    import {Dialog} from 'occulite-ui';
    import {t} from 'occulite-ui/i18n';

    import {post, put} from './api.js';
    import type {Config, UserView, View} from './model.js';

    let {open, config, user, onclose, onsaved}: {open: boolean; config: Config; user: UserView | undefined; onclose: () => void; onsaved: (c: Config) => void} = $props();

    let name = $state('');
    let auth = $state('SHA-256');
    let priv = $state('AES');
    let view = $state<View>('all');
    let authPw = $state('');
    let privPw = $state('');
    let error = $state('');
    let busy = $state(false);

    $effect(() => {
        if (!open) return;
        name = user?.name ?? '';
        auth = user?.auth ?? 'SHA-256';
        priv = user?.priv ?? 'AES';
        view = user?.view ?? 'all';
        authPw = '';
        privPw = '';
        error = '';
    });

    const isNew = $derived(user === undefined);
    const needPasswords = $derived(isNew || authPw !== '' || privPw !== '' || auth !== user?.auth);
    const min = $derived(config.min_password);
    const valid = $derived(
        /^[A-Za-z0-9._@-]{1,32}$/.test(name) && (!needPasswords || (authPw.length >= min && privPw.length >= min)),
    );

    async function save() {
        busy = true;
        error = '';
        try {
            const body: Record<string, string> = {name, auth, priv, view};
            if (needPasswords) {
                body.auth_password = authPw;
                body.priv_password = privPw;
            }
            const c = isNew ? await post<Config>('api/v1/users', body) : await put<Config>(`api/v1/users/${encodeURIComponent(user!.name)}`, body);
            onsaved(c);
        } catch (e) {
            error = (e as Error).message;
        } finally {
            busy = false;
        }
    }
</script>

<Dialog {open} title={isNew ? t('New SNMPv3 user') : t('SNMPv3 user {name}', {name: user?.name ?? ''})} width="32rem" closable={!busy} {onclose} testId="user-dialog">
    <div class="snmp-form">
        <label for="u-name">{t('User name')}</label>
        <input class="hmm-input" id="u-name" type="text" bind:value={name} disabled={!isNew} maxlength="32" autocomplete="off" data-testid="user-name" />
        <label for="u-auth">{t('Authentication')}</label>
        <select class="hmm-select" id="u-auth" bind:value={auth}>
            {#each config.auths as a (a)}<option value={a}>{a}{a === 'SHA-256' ? ' ' + t('(default)') : ''}</option>{/each}
        </select>
        <label for="u-priv">{t('Privacy')}</label>
        <select class="hmm-select" id="u-priv" bind:value={priv}>
            {#each config.privs as p (p)}<option value={p}>{p === 'AES' ? 'AES-128 ' + t('(default)') : p}</option>{/each}
        </select>
        {#if priv !== 'AES'}<p class="snmp-help snmp-span">{t('Not every monitoring system speaks AES-192 or AES-256 the same way; check yours, or keep AES-128.')}</p>{/if}
        <label for="u-view">{t('May read')}</label>
        <select class="hmm-select" id="u-view" bind:value={view}>
            <option value="all">{t('Everything')}</option>
            <option value="standard">{t('The standard MIBs only')}</option>
            <option value="homematic">{t('The Homematic tree only')}</option>
        </select>
        <label for="u-apw">{t('Authentication password')}</label>
        <input class="hmm-input" id="u-apw" type="password" bind:value={authPw} autocomplete="new-password" placeholder={isNew ? '' : t('unchanged')} data-testid="user-authpw" />
        <label for="u-ppw">{t('Privacy password')}</label>
        <input class="hmm-input" id="u-ppw" type="password" bind:value={privPw} autocomplete="new-password" placeholder={isNew ? '' : t('unchanged')} data-testid="user-privpw" />
        <p class="snmp-help snmp-span">
            {t('At least {n} characters each. The passwords are stored as their derived keys and never shown again.', {n: min})}
            {#if !isNew && auth !== user?.auth}{t('A new authentication protocol needs both passwords again.')}{/if}
        </p>
    </div>
    <p class="snmp-error" role="alert">{error}</p>
    {#snippet buttons()}
        <button class="hmm-button" onclick={onclose} disabled={busy}>{t('Cancel')}</button>
        <button class="hmm-button snmp-primary" onclick={save} disabled={!valid || busy} data-testid="user-save">{t('Save')}</button>
    {/snippet}
</Dialog>
