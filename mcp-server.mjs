import { evaluateCanaryDecisionManifest, inspectCanaryDecisionManifestJson } from './lib/canary-decision-proof.mjs'
const VERSION = '0.1.0'; const LIMIT = 6 * 1024 * 1024
const tools = [
  { name: 'canary_decision_inspect', description: 'Inspect redacted canary evidence counts and hashes.', inputSchema: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string', maxLength: 4194304 } }, additionalProperties: false } },
  { name: 'canary_decision_verify', description: 'Verify an inline canary decision without querying metrics or executing rollout.', inputSchema: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string', maxLength: 4194304 } }, additionalProperties: false } }
]
const ok = (id, result) => ({ jsonrpc: '2.0', id, result }); const err = (id, error) => ({ jsonrpc: '2.0', id, error: { code: -32000, message: error.code || 'VERIFICATION_ERROR', data: { code: error.code || 'VERIFICATION_ERROR' } } })
async function dispatch(request) {
  if (request.method === 'initialize') return ok(request.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'dsh-canary-decision-proof', version: VERSION } })
  if (request.method === 'tools/list') return ok(request.id, { tools })
  if (request.method === 'tools/call') { const manifestJson = request.params?.arguments?.manifestJson; const value = request.params?.name === 'canary_decision_inspect' ? inspectCanaryDecisionManifestJson(manifestJson) : request.params?.name === 'canary_decision_verify' ? evaluateCanaryDecisionManifest(manifestJson) : (() => { throw Object.assign(new Error('unknown tool'), { code: 'METHOD_NOT_FOUND' }) })(); return ok(request.id, { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value, isError: false }) }
  throw Object.assign(new Error('unknown method'), { code: 'METHOD_NOT_FOUND' })
}
let buffer = ''; process.stdin.setEncoding('utf8'); process.stdin.on('data', async chunk => { buffer += chunk; if (buffer.length > LIMIT) process.exit(1); let cut; while ((cut = buffer.indexOf('\n')) >= 0) { const line = buffer.slice(0, cut); buffer = buffer.slice(cut + 1); if (!line) continue; let request; let response; try { request = JSON.parse(line); response = await dispatch(request) } catch (error) { response = err(request?.id ?? null, error) } process.stdout.write(`${JSON.stringify(response)}\n`) } })
