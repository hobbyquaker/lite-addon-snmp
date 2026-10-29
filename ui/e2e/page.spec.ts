import {expect, test} from '@playwright/test';

// One run through the page: a user, a community, a selection with a live count, the device table
// following it, the status. The steps depend on each other (one daemon, one configuration).
test.describe.configure({mode: 'serial'});

test('starts with no credential and says so', async ({page}) => {
    await page.goto('./');
    await page.getByRole('tab', {name: /Access/}).click();
    await expect(page.getByTestId('no-credentials')).toBeVisible();
});

test('adds an SNMPv3 user; short passwords are refused', async ({page}) => {
    await page.goto('./');
    await page.getByRole('tab', {name: /Access/}).click();
    await page.getByTestId('user-add').click();
    await page.getByTestId('user-name').fill('nms');
    await page.getByTestId('user-authpw').fill('short');
    await page.getByTestId('user-privpw').fill('short');
    await expect(page.getByTestId('user-save')).toBeDisabled();
    await page.getByTestId('user-authpw').fill('authpassword1');
    await page.getByTestId('user-privpw').fill('privpassword1');
    await page.getByTestId('user-save').click();
    await expect(page.getByTestId('users')).toContainText('nms');
    await expect(page.getByTestId('users')).toContainText('authPriv · SHA-256 · AES-128');
    await expect(page.getByTestId('users')).toContainText("-A '<auth password>'");
    await expect(page.getByTestId('no-credentials')).toHaveCount(0);
});

test('adds a community from local networks', async ({page}) => {
    await page.goto('./');
    await page.getByRole('tab', {name: /Access/}).click();
    await page.getByTestId('community-add').click();
    await page.getByTestId('community-name').fill('public-ccu');
    await page.getByTestId('community-save').click();
    await expect(page.getByTestId('communities')).toContainText('public-ccu');
    await expect(page.getByTestId('communities')).toContainText('local');
});

test('builds a selection with a live count and uses it for the device table', async ({page}) => {
    await page.goto('./');
    await page.getByRole('tab', {name: /Selections/}).click();
    await page.getByTestId('selection-add').click();
    const dlg = page.getByTestId('selection-editor');
    await dlg.getByRole('textbox', {name: 'Name'}).fill('Hall');
    const count = page.getByTestId('selection-count');
    await expect(count).toContainText('4 devices');
    // the forwarder's rules: rooms come from the suggestions
    await dlg.getByRole('textbox', {name: 'Rooms'}).fill('Flur');
    await dlg.getByRole('textbox', {name: 'Rooms'}).press('Enter');
    await expect(count).toContainText('2 devices');
    // a key glob keeps the devices with a PRESS_* datapoint
    await dlg.getByRole('textbox', {name: 'Datapoints', exact: true}).fill('PRESS_*');
    await dlg.getByRole('textbox', {name: 'Datapoints', exact: true}).press('Enter');
    await expect(count).toContainText('2 devices');
    await expect(page.getByTestId('selection-preview')).toContainText('Taster Flur');
    // excluding the remote in the device tree
    await dlg.getByRole('tab', {name: /Devices and channels/}).click();
    await dlg.getByRole('treeitem').filter({hasText: 'Taster Flur'}).getByRole('button', {name: '×'}).click();
    await expect(count).toContainText('1 devices');
    await page.getByTestId('selection-save').click();
    await expect(page.getByTestId('selections')).toContainText('Hall');

    await page.getByRole('tab', {name: /Tables/}).click();
    await page.getByTestId('device-table-selection').selectOption({label: 'Hall'});
    await expect(page.getByTestId('device-rows-count')).toContainText('1 rows', {timeout: 10_000});
});

test('the status counts the requests', async ({page}) => {
    await page.goto('./');
    await page.getByRole('tab', {name: /Status/}).click();
    await expect(page.getByTestId('status')).toContainText('Listening');
    await expect(page.getByTestId('status')).toContainText('yes');
});

test('the agent tab offers the MIB and the engine id', async ({page}) => {
    await page.goto('./');
    await expect(page.getByTestId('engine-id')).toHaveText(/^80001f8805[0-9a-f]{32}$/);
    const dl = page.waitForEvent('download');
    await page.getByTestId('mib-download').click();
    expect((await dl).suggestedFilename()).toBe('LITE-SNMP-MIB.txt');
});

test.describe('in German', () => {
    test.use({locale: 'de-DE'});
    test('the page speaks German', async ({page}) => {
        await page.goto('./');
        await expect(page.getByRole('tab', {name: /Zugang/})).toBeVisible();
        await expect(page.getByText('SNMP-Anfragen beantworten')).toBeVisible();
    });
});
