import {test} from '@playwright/test';

// The readme's screenshots (SCREENSHOTS=1 npx playwright test screenshots): German, light and dark.
test.skip(!process.env.SCREENSHOTS, 'only on demand');
test.use({locale: 'de-DE', viewport: {width: 1200, height: 820}});

for (const scheme of ['light', 'dark'] as const) {
    test(`screenshots ${scheme}`, async ({page}) => {
        await page.emulateMedia({colorScheme: scheme});
        const suffix = scheme === 'dark' ? '-dunkel' : '';
        const out = (n: string) => `../docs/screenshots/${n}${suffix}.png`;
        await page.goto('./');
        await page.getByRole('tab', {name: /Zugang/}).click();
        if (!(await page.getByTestId('users').getByText('nms').count())) {
            await page.getByTestId('user-add').click();
            await page.getByTestId('user-name').fill('nms');
            await page.getByTestId('user-authpw').fill('authpassword1');
            await page.getByTestId('user-privpw').fill('privpassword1');
            await page.getByTestId('user-save').click();
        }
        await page.getByRole('tab', {name: /Agent/}).click();
        await page.screenshot({path: out('01-agent')});
        await page.getByRole('tab', {name: /Zugang/}).click();
        await page.screenshot({path: out('02-zugang')});
        await page.getByRole('tab', {name: /Auswahl/}).click();
        await page.getByTestId('selection-add').click();
        const dlg = page.getByTestId('selection-editor');
        await dlg.getByRole('textbox', {name: 'Name'}).fill('Batterien');
        await dlg.getByRole('textbox', {name: 'Datenpunkte', exact: true}).fill('LOW*');
        await dlg.getByRole('textbox', {name: 'Datenpunkte', exact: true}).press('Enter');
        await page.waitForTimeout(800);
        await page.screenshot({path: out('03-auswahl')});
        await dlg.getByRole('tab', {name: /Geräte und Kanäle/}).click();
        await page.waitForTimeout(300);
        await page.screenshot({path: out('04-auswahl-geraete')});
        await page.keyboard.press('Escape');
        await page.getByRole('tab', {name: /Status/}).click();
        await page.waitForTimeout(500);
        await page.screenshot({path: out('05-status')});
    });
}
