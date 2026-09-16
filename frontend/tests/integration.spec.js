import { test, expect } from '@playwright/test'
import { resolve } from 'node:path'

const ui = process.env.ULPF_UI_URL || 'http://127.0.0.1:5173'

const samples = [
  ['fortigate.log', 'Fortinet', 'keyvalue', '10.10.20.15', '198.51.100.22', 'tcp', 'allow', 'srcip'],
  ['cisco_asa.log', 'Cisco', 'syslog', '203.0.113.45', '10.20.4.18', 'tcp', 'allow', 'srcip'],
  ['paloalto.csv', 'Palo Alto Networks', 'csv', '10.1.4.25', '203.0.113.80', 'tcp', 'allow', 'Source address'],
  ['generic_cef.log', 'Acme Security', 'cef', '10.4.2.19', '198.51.100.44', 'tcp', 'deny', 'src'],
  ['firewall.json', 'Unknown', 'json', '192.0.2.25', '198.51.100.10', 'tcp', 'allow', 'source.address'],
]

test('Live Processor handles all five samples and traces stored data', async ({ page }) => {
  await page.goto(ui)
  await expect(page.getByText('CONNECTED')).toBeVisible()
  for (const [filename, vendor, format, source, destination, transport, action, sourceField] of samples) {
    await page.locator('#sample-select').selectOption(filename)
    await expect(page.locator('#raw-input')).not.toBeEmpty()
    await page.locator('#process-button').click()
    await expect(page.locator('.result-panel .section-meta')).toContainText('EVENT ID /')
    await expect(page.locator('.summary-facts')).toContainText(vendor)
    await expect(page.locator('.summary-facts')).toContainText(transport)
    await expect(page.locator('.summary-facts')).toContainText(action)
    await expect(page.locator('.flow-address')).toContainText(source)
    await expect(page.locator('.flow-address')).toContainText(destination)
    await expect(page.locator('.pipeline-list')).toContainText(format.toUpperCase())
    await expect(page.locator('.pipeline-list')).toContainText('PARSER SELECTION')
    await page.getByRole('tab', { name: /FIELD TRACEABILITY/ }).click()
    await expect(page.locator('#result-body table tbody tr').first()).toBeVisible()
    await expect(page.locator('#result-body')).toContainText(sourceField)
    await page.getByRole('tab', { name: /PRESERVED FIELDS/ }).click()
    await expect(page.locator('#result-body')).toContainText('RETAINED SOURCE ATTRIBUTES')
    await page.getByRole('tab', { name: 'RAW & INTEGRITY' }).click()
    await page.locator('#verify-button').click()
    await expect(page.locator('.verification')).toContainText('matches its SHA-256 digest')
    await page.getByRole('tab', { name: 'JSON DOCUMENT' }).click()
    await expect(page.locator('.json-block')).toContainText('"source"')
    await expect(page.locator('.json-block')).toContainText('"provenance"')
  }
  await page.getByRole('button', { name: /Event Explorer/ }).click()
  await expect(page.locator('.events-table .event-row').first()).toBeVisible()
  expect(await page.locator('.events-table .event-row').count()).toBeGreaterThanOrEqual(5)
  await page.locator('.events-table .event-row').first().click()
  await expect(page.locator('.result-panel .section-meta')).toContainText('EVENT ID /')
})

test('upload control stores log, JSON, and CSV samples and exposes integrity', async ({ page }) => {
  await page.goto(ui)
  for (const filename of ['fortigate.log', 'firewall.json', 'paloalto.csv']) {
    await page.locator('#upload-file').setInputFiles(resolve(`../samples/${filename}`))
    await expect(page.locator('.upload-summary')).toContainText('1 received')
    await expect(page.locator('.result-panel .section-meta')).toContainText('EVENT ID /')
    await page.getByRole('tab', { name: 'RAW & INTEGRITY' }).click()
    await page.locator('#verify-button').click()
    await expect(page.locator('.verification')).toContainText('matches its SHA-256 digest')
  }
})

test('stored filters, inspector, schema search, and factual views', async ({ page }) => {
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto(ui)
  await page.getByRole('button', { name: /Event Explorer/ }).click()
  await expect(page.locator('.event-row').first()).toBeVisible()
  await page.locator('#filter-vendor').selectOption('Fortinet')
  await page.locator('#filter-format').selectOption('keyvalue')
  await page.locator('#filter-action').selectOption('allow')
  await page.locator('#filter-severity').selectOption('notice')
  await page.locator('#filter-search').fill('10.10.20.15')
  const filtered = page.waitForResponse(response => response.url().includes('/api/v1/events?') && response.url().includes('vendor=Fortinet'))
  await page.locator('#filter-button').click()
  await filtered
  await expect(page.locator('.event-row').first()).toBeVisible()
  expect((await page.locator('.event-row').allTextContents()).every(text => text.includes('Fortinet'))).toBe(true)
  await page.locator('.event-row').first().click()
  await expect(page.locator('.summary-facts')).toContainText('Fortinet')
  await page.getByRole('tab', { name: /FIELD TRACEABILITY/ }).click()
  await expect(page.locator('#result-body')).toContainText('srcip')
  await page.getByRole('tab', { name: 'RAW & INTEGRITY' }).click()
  await expect(page.locator('.raw-block')).toContainText('devname=')
  await page.locator('#verify-button').click()
  await expect(page.locator('.verification')).toContainText('matches its SHA-256 digest')
  await page.getByRole('button', { name: /Parser Registry/ }).click()
  await expect(page.locator('tbody tr')).toHaveCount(6)
  await page.getByRole('button', { name: /Universal Schema/ }).click()
  await page.locator('#schema-search').fill('community_id')
  await expect(page.locator('.schema-item')).toHaveCount(1)
  await expect(page.locator('.schema-item')).toContainText('network')
  await page.getByRole('button', { name: /Overview/ }).click()
  await expect(page.locator('.recent-panel .event-row').first()).toBeVisible()
  await page.getByRole('button', { name: /System/ }).click()
  await expect(page.locator('#content')).toContainText('SQLite')
  expect(errors).toEqual([])
})

test('compact error states preserve the workstation', async ({ page }) => {
  await page.goto(ui)
  await page.locator('#process-button').click()
  await expect(page.locator('.notice.error')).toContainText('Enter a raw event')
  await page.locator('#raw-input').fill('{bad json')
  await page.locator('#process-button').click()
  await expect(page.locator('.result-panel')).toContainText('failed')
  await expect(page.locator('.result-aside')).toContainText('Parser failed')
  await page.locator('#raw-input').fill('unrecognized raw text')
  await page.locator('#process-button').click()
  await expect(page.locator('.result-panel')).toContainText('partial')
  await page.locator('#upload-file').setInputFiles({name:'unsupported.exe',mimeType:'application/octet-stream',buffer:Buffer.from('test')})
  await expect(page.locator('.notice.error')).toContainText('Allowed extensions')
  await page.locator('#upload-file').setInputFiles({name:'bad.csv',mimeType:'text/csv',buffer:Buffer.from('a,b,c\n1,2')})
  await expect(page.locator('.upload-summary')).toContainText('1 received')
  await expect(page.locator('.result-panel')).toContainText('partial')
  await page.locator('#upload-file').setInputFiles({name:'large.log',mimeType:'text/plain',buffer:Buffer.alloc(5_000_001,65)})
  await expect(page.locator('.notice.error')).toContainText('5 MB')
})

test('API unavailability is shown inline', async ({ page }) => {
  await page.route('**/api/v1/**', route => route.abort())
  await page.goto(ui)
  await expect(page.locator('.system-indicator')).toContainText('UNAVAILABLE')
  await page.locator('#raw-input').fill('unrecognized raw text')
  await page.locator('#process-button').click()
  await expect(page.locator('.notice.error')).toContainText('Processing API is unavailable')
})
