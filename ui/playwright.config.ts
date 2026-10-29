import {defineConfig} from '@playwright/test';

// The page against the daemon and the fake system (scripts/dev-serve.sh): build the page first
// (npm run build). Run as `env -u WAYLAND_DISPLAY npx playwright test` on WSL.
export default defineConfig({
    testDir: 'e2e',
    timeout: 30_000,
    workers: 1,
    use: {baseURL: 'http://127.0.0.1:18296/addons/snmp/', locale: 'en-GB'},
    webServer: {
        command: '../scripts/dev-serve.sh',
        url: 'http://127.0.0.1:18296/addons/snmp/api/v1/health?ready=1',
        reuseExistingServer: false,
        timeout: 120_000,
    },
});
