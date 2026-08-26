import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises'
import { isAbsolute, relative, resolve } from 'node:path'

const MAX_FILE = 4 * 1024 * 1024
const HEX = /^[a-f0-9]{64}$/
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/
const SECRET_VALUE = /(?:bearer\s+[a-z0-9._-]{12,}|(?:sk|ghp|github_pat)_[a-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i
const stable = value => JSON.stringify(value, (_, child) => child && typeof child === 'object' && !Array.isArray(child) ? Object.fromEntries(Object.entries(child).sort(([a], [b]) => a.localeCompare(b))) : child)
export const sha256 = value => createHash('sha256').update(value).digest('hex')
const fail = (code, message) => Object.assign(new Error(message), { code })
const hash = (value, label) => { if (typeof value !== 'string' || !HEX.test(value)) throw fail('INVALID_MANIFEST', `${label} must be lowercase SHA-256`) }
const boundedId = (value, label) => { if (typeof value !== 'string' || !ID.test(value)) throw fail('INVALID_MANIFEST', `${label} must be a bounded public id`) }
const timestamp = (value, label) => { const parsed = Date.parse(value); if (!Number.isFinite(parsed)) throw fail('INVALID_TIME', `${label} must be an ISO timestamp`); return parsed }

function rejectSecrets(value, path = '$') {
  if (typeof value === 'string' && SECRET_VALUE.test(value)) throw fail('SECRET_MATERIAL', `secret-shaped value rejected at ${path}`)
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if (/(?:secret|password|credential|api[_-]?key|private[_-]?key|authorization|cookie|raw|body|content|log|prompt|chat)$/i.test(key) && (typeof child === 'string' || typeof child === 'number')) throw fail('SECRET_MATERIAL', `sensitive field rejected at ${path}.${key}`)
    rejectSecrets(child, `${path}.${key}`)
  }
}

function integer(value, label, min, max) { if (!Number.isSafeInteger(value) || value < min || value > max) throw fail('INVALID_MANIFEST', `${label} invalid`) }

function parseManifest(input) {
  let manifest
  try { manifest = typeof input === 'string' ? JSON.parse(input) : structuredClone(input) } catch { throw fail('INVALID_MANIFEST', 'manifest must be JSON') }
  if (!manifest || manifest.schemaVersion !== 1) throw fail('INVALID_MANIFEST', 'schemaVersion 1 required')
  rejectSecrets(manifest); boundedId(manifest.proofId, 'proofId')
  const evaluationMs = timestamp(manifest.evaluationTime, 'evaluationTime')
  const rollout = manifest.rollout || {}
  for (const key of ['rolloutReceiptSha256', 'canaryArtifactSha256', 'baselineArtifactSha256', 'environmentHash', 'policySha256']) hash(rollout[key], `rollout.${key}`)
  if (rollout.canaryArtifactSha256 === rollout.baselineArtifactSha256) throw fail('INVALID_MANIFEST', 'canary and baseline artifacts must differ')
  const startedMs = timestamp(rollout.startedAt, 'rollout.startedAt')
  const policy = manifest.policy || {}
  integer(policy.requiredWindows, 'policy.requiredWindows', 1, 100)
  integer(policy.minWindowMs, 'policy.minWindowMs', 1000, 7 * 86400000)
  integer(policy.maxCanaryTrafficBps, 'policy.maxCanaryTrafficBps', 1, 9999)
  integer(policy.maxEvidenceAgeMs, 'policy.maxEvidenceAgeMs', 1000, 365 * 86400000)
  integer(policy.minDistinctObservers, 'policy.minDistinctObservers', 1, 100)
  if (!Array.isArray(policy.metrics) || !policy.metrics.length || policy.metrics.length > 64) throw fail('INVALID_MANIFEST', 'policy.metrics invalid')
  const metrics = new Map()
  for (const [index, metric] of policy.metrics.entries()) {
    hash(metric?.metricIdHash, `metrics[${index}].metricIdHash`)
    if (!['higher-better', 'lower-better'].includes(metric.direction)) throw fail('INVALID_MANIFEST', 'metric direction invalid')
    integer(metric.maxRegressionBps, 'maxRegressionBps', 0, 10000)
    integer(metric.minSampleCount, 'minSampleCount', 1, 1000000000)
    integer(metric.failureLimit, 'failureLimit', 1, policy.requiredWindows)
    if (metrics.has(metric.metricIdHash)) throw fail('INVALID_MANIFEST', 'duplicate metric')
    metrics.set(metric.metricIdHash, metric)
  }
  if (!Array.isArray(manifest.exposures) || manifest.exposures.length !== policy.requiredWindows) throw fail('INVALID_MANIFEST', 'exposures must match requiredWindows')
  const windowIds = new Set()
  const exposures = manifest.exposures.map((row, index) => {
    if (row?.sequence !== index + 1) throw fail('INVALID_MANIFEST', 'exposure sequence must be contiguous')
    hash(row.windowIdHash, `exposures[${index}].windowIdHash`); if (windowIds.has(row.windowIdHash)) throw fail('INVALID_MANIFEST', 'duplicate window')
    windowIds.add(row.windowIdHash); integer(row.canaryTrafficBps, 'canaryTrafficBps', 1, 9999)
    const beganMs = timestamp(row.startedAt, 'exposure.startedAt'); const endedMs = timestamp(row.endedAt, 'exposure.endedAt')
    return { ...row, beganMs, endedMs }
  })
  const decision = manifest.decision || {}; if (!['promote', 'abort', 'pause'].includes(decision.declared)) throw fail('INVALID_MANIFEST', 'decision.declared invalid'); hash(decision.decisionReceiptSha256, 'decision.decisionReceiptSha256'); const decidedMs = timestamp(decision.decidedAt, 'decision.decidedAt')
  const expectedCount = policy.requiredWindows * metrics.size * 2
  if (!Array.isArray(manifest.observations) || !manifest.observations.length || manifest.observations.length > 12800) throw fail('INVALID_MANIFEST', 'observations invalid')
  const keys = new Set(); const observationIds = new Set()
  const observations = manifest.observations.map((row, index) => {
    for (const key of ['observationIdHash', 'windowIdHash', 'metricIdHash', 'observerHash', 'rolloutReceiptSha256', 'policySha256']) hash(row?.[key], `observations[${index}].${key}`)
    if (!['baseline', 'canary'].includes(row.cohort)) throw fail('INVALID_MANIFEST', 'observation cohort invalid')
    integer(row.valueMicros, 'valueMicros', 1, 1000000000000); integer(row.sampleCount, 'sampleCount', 0, 1000000000)
    if (observationIds.has(row.observationIdHash)) throw fail('INVALID_MANIFEST', 'duplicate observation id'); observationIds.add(row.observationIdHash)
    const key = `${row.windowIdHash}:${row.metricIdHash}:${row.cohort}`; if (keys.has(key)) throw fail('INVALID_MANIFEST', 'duplicate observation cell'); keys.add(key)
    return { ...row, observedMs: timestamp(row.observedAt, 'observation.observedAt') }
  })
  return { manifest, evaluationMs, rollout, startedMs, policy, metrics, exposures, windowIds, decision, decidedMs, expectedCount, observations, keys }
}

const regressionBps = (baseline, canary, direction) => {
  const adverse = direction === 'higher-better' ? baseline - canary : canary - baseline
  if (adverse <= 0) return 0
  return Number((BigInt(adverse) * 10000n) / BigInt(baseline))
}

export function inspectCanaryDecisionManifestJson(manifestJson) {
  const { manifest, rollout, policy, metrics, exposures, observations } = parseManifest(manifestJson)
  return { schemaVersion: 1, proofIdHash: sha256(manifest.proofId), canaryArtifactSha256: rollout.canaryArtifactSha256, baselineArtifactSha256: rollout.baselineArtifactSha256, declaredDecision: manifest.decision.declared, metricCount: metrics.size, windowCount: exposures.length, observationCount: observations.length, queriesLiveMetrics: false, executesRollout: false }
}

export function evaluateCanaryDecisionManifest(manifestJson) {
  const { manifest, evaluationMs, rollout, startedMs, policy, metrics, exposures, windowIds, decision, decidedMs, expectedCount, observations, keys } = parseManifest(manifestJson)
  const exposureValid = exposures.every((row, index) => row.canaryTrafficBps <= policy.maxCanaryTrafficBps && row.beganMs >= startedMs && row.endedMs > row.beganMs && row.endedMs - row.beganMs >= policy.minWindowMs && row.endedMs <= decidedMs && (index === 0 || row.beganMs >= exposures[index - 1].endedMs))
  const exactMatrix = observations.length === expectedCount && keys.size === expectedCount && [...windowIds].every(window => [...metrics.keys()].every(metric => keys.has(`${window}:${metric}:baseline`) && keys.has(`${window}:${metric}:canary`)))
  const observers = new Set(observations.map(row => row.observerHash)); const distinctObserversSatisfied = observers.size >= policy.minDistinctObservers
  const evidenceBound = observations.every(row => row.rolloutReceiptSha256 === rollout.rolloutReceiptSha256 && row.policySha256 === rollout.policySha256 && windowIds.has(row.windowIdHash) && metrics.has(row.metricIdHash))
  const chronologyValid = observations.every(row => row.observedMs >= startedMs && row.observedMs <= decidedMs) && decidedMs >= exposures.at(-1).endedMs && decidedMs <= evaluationMs
  const evidenceFresh = observations.every(row => evaluationMs - row.observedMs >= 0 && evaluationMs - row.observedMs <= policy.maxEvidenceAgeMs)
  const samplesSufficient = observations.every(row => metrics.has(row.metricIdHash) && row.sampleCount >= metrics.get(row.metricIdHash).minSampleCount)
  const metricResults = [...metrics].map(([metricIdHash, rule]) => {
    const windows = exposures.map(exposure => {
      const baseline = observations.find(row => row.windowIdHash === exposure.windowIdHash && row.metricIdHash === metricIdHash && row.cohort === 'baseline')
      const canary = observations.find(row => row.windowIdHash === exposure.windowIdHash && row.metricIdHash === metricIdHash && row.cohort === 'canary')
      if (!baseline || !canary) return { windowIdHash: exposure.windowIdHash, complete: false, regressionBps: null, breached: null }
      const regression = regressionBps(baseline.valueMicros, canary.valueMicros, rule.direction)
      return { windowIdHash: exposure.windowIdHash, complete: true, regressionBps: regression, breached: regression > rule.maxRegressionBps }
    })
    const breachedWindows = windows.filter(row => row.breached).length
    return { metricIdHash, direction: rule.direction, maxRegressionBps: rule.maxRegressionBps, failureLimit: rule.failureLimit, breachedWindows, failed: breachedWindows >= rule.failureLimit, windows }
  })
  const evidenceComplete = exposureValid && exactMatrix && distinctObserversSatisfied && evidenceBound && chronologyValid && evidenceFresh && samplesSufficient
  const computedDecision = !evidenceComplete ? 'pause' : metricResults.some(row => row.failed) ? 'abort' : 'promote'
  const decisionMatches = decision.declared === computedDecision
  return { schemaVersion: 1, verdict: decisionMatches ? 'verified-decision' : 'not-verified', proofIdHash: sha256(manifest.proofId), rolloutReceiptSha256: rollout.rolloutReceiptSha256, canaryArtifactSha256: rollout.canaryArtifactSha256, baselineArtifactSha256: rollout.baselineArtifactSha256, environmentHash: rollout.environmentHash, policySha256: rollout.policySha256, decisionReceiptSha256: decision.decisionReceiptSha256, declaredDecision: decision.declared, computedDecision, checks: { exposureValid, exactMatrix, distinctObserversSatisfied, evidenceBound, chronologyValid, evidenceFresh, samplesSufficient, decisionMatches }, disclosures: { metricCount: metrics.size, windowCount: exposures.length, observationCount: observations.length, expectedObservationCount: expectedCount, distinctObserverCount: observers.size }, metrics: metricResults, executesRollout: false, grantsAuthorization: false, authenticatesReceipts: false, queriesLiveMetrics: false, provesStatisticalSignificance: false, provesUserOutcomeCorrectness: false, destructiveActions: false }
}

async function safeManifest(root, manifestPath) {
  if (typeof manifestPath !== 'string' || !manifestPath || manifestPath.length > 512 || isAbsolute(manifestPath)) throw fail('PATH_ESCAPE', 'manifestPath must be workspace-relative')
  const absolute = resolve(root, manifestPath); const rel = relative(root, absolute); if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'manifestPath escapes workspaceRoot')
  let cursor = root; let stat
  for (const [index, part] of rel.split(/[\\/]/).entries()) { cursor = resolve(cursor, part); stat = await lstat(cursor).catch(() => { throw fail('MISSING_MANIFEST', 'manifest missing') }); if (stat.isSymbolicLink()) throw fail('UNSAFE_MANIFEST', 'manifest path contains symlink'); if (index < rel.split(/[\\/]/).length - 1 && !stat.isDirectory()) throw fail('UNSAFE_MANIFEST', 'manifest parent invalid') }
  if (!stat.isFile() || stat.size > MAX_FILE) throw fail('UNSAFE_MANIFEST', 'manifest must be a regular file no larger than 4 MiB')
  const realRel = relative(await realpath(root), await realpath(absolute)); if (realRel.startsWith('..') || isAbsolute(realRel)) throw fail('PATH_ESCAPE', 'real manifest escapes workspaceRoot')
  return readFile(absolute, 'utf8')
}

async function safeArtifactDir(root, artifactDir) {
  if (typeof artifactDir !== 'string' || !artifactDir || artifactDir.length > 512 || isAbsolute(artifactDir)) throw fail('PATH_ESCAPE', 'artifactDir must be workspace-relative')
  const dir = resolve(root, artifactDir); const rel = relative(root, dir); if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'artifactDir escapes workspaceRoot')
  let cursor = root
  for (const part of rel.split(/[\\/]/)) { cursor = resolve(cursor, part); try { const stat = await lstat(cursor); if (stat.isSymbolicLink() || !stat.isDirectory()) throw fail('UNSAFE_ARTIFACT_DIR', 'artifactDir components must be real directories') } catch (error) { if (error.code !== 'ENOENT') throw error; await mkdir(cursor) } }
  return dir
}

export async function verifyCanaryDecisionManifest({ workspaceRoot, manifestPath, artifactDir }) {
  const root = resolve(workspaceRoot); const report = evaluateCanaryDecisionManifest(await safeManifest(root, manifestPath)); const bytes = Buffer.from(`${stable(report)}\n`); const digest = sha256(bytes); const dir = await safeArtifactDir(root, artifactDir); const output = resolve(dir, `canary-decision-proof-${digest}.json`)
  try { await writeFile(output, bytes, { flag: 'wx' }) } catch (error) { if (error.code !== 'EEXIST') throw error; if (!(await readFile(output)).equals(bytes)) throw fail('ARTIFACT_DIVERGED', 'content-addressed artifact diverged') }
  const readBack = await readFile(output); if (sha256(readBack) !== digest) throw fail('READBACK_FAILED', 'artifact read-back failed')
  return { ...report, artifact: { path: relative(root, output).replaceAll('\\', '/'), sha256: digest, verifiedByReadBack: true } }
}
