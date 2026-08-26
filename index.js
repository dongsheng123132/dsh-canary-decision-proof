import { inspectCanaryDecisionManifestJson, verifyCanaryDecisionManifest } from './lib/canary-decision-proof.mjs'
export const name = 'dsh-canary-decision-proof'
export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]
const define = value => ({ ...value, output: { schema: {}, render: renderJson } })
export function createDefinitions(_ctx = {}, config = {}) {
  const workspaceRoot = config.workspaceRoot || process.cwd()
  return [
    define({ name: 'dsh_canary_decision_inspect', description: 'Inspect bounded hashes and counts from an explicit canary decision manifest.', parameters: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string' } }, additionalProperties: false }, execute: async ({ manifestJson }) => inspectCanaryDecisionManifestJson(manifestJson) }),
    define({ name: 'dsh_canary_decision_verify', description: 'Verify a canary promote, abort or pause decision and write a redacted content-addressed report.', parameters: { type: 'object', required: ['manifestPath', 'artifactDir'], properties: { manifestPath: { type: 'string' }, artifactDir: { type: 'string' } }, additionalProperties: false }, execute: async args => verifyCanaryDecisionManifest({ workspaceRoot, ...args }) })
  ]
}
export function apply(ctx, config = {}) { for (const definition of createDefinitions(ctx, config)) ctx.tools.register(definition) }
