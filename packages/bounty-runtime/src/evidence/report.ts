import type { VerifiedEvidenceBundle } from './writer.js';

export function renderReport(bundle: VerifiedEvidenceBundle): string {
  assertBundleShape(bundle);
  const title = bundle.manifest.result === 'anomalous'
    ? '# Candidate for human validation'
    : '# Experiment result';
  const impact = bundle.candidate?.impact.summary ?? 'No independently verified confidentiality or integrity impact was established.';
  const observed = bundle.diff.summary;
  const expected = bundle.experiment.expectedSafeOutcome;
  const evidenceIds = bundle.observations.map((observation) => `- ${observation.observationId}`).join('\n');
  const cleanup = bundle.manifest.cleanupStatus === 'not-required'
    ? 'No mutation was planned; cleanup was not required.'
    : `Cleanup status: ${bundle.manifest.cleanupStatus}.`;
  const reproduction = bundle.plan.operations
    .filter((operation) => operation.phase !== 'cleanup')
    .map((operation, index) => `${index + 1}. Catalog operation \`${operation.operationId}\` as actor \`${operation.actor}\` (step \`${operation.stepId}\`).`)
    .join('\n');

  return [
    title,
    '',
    `**Run:** \`${bundle.runId}\``,
    '',
    '## Summary',
    `This document records the sanitized result of experiment \`${bundle.experiment.id}\` version ${bundle.experiment.version}. It is a sanitized research record for human review.`,
    '',
    '## Affected GitHub Surface',
    `The reviewed surface is the catalog operation set for repository \`${bundle.experiment.scopeTarget}\`.`,
    '',
    '## Preconditions',
    `Policy \`${bundle.policy.policyVersion}\` was ${bundle.policy.state}; the run used a verified lab repository and the declared access-boundary expectation.`,
    '',
    '## Reproduction',
    reproduction || 'No executable reproduction was emitted.',
    '',
    '## Observed Result',
    observed,
    `Referenced observation IDs: ${bundle.observations.map((observation) => observation.observationId).join(', ') || 'none'}.`,
    '',
    '## Expected Result',
    expected,
    `Expected-boundary evidence reference: ${bundle.diff.comparedObservationIds.join(', ')}.`,
    '',
    '## Impact',
    impact,
    '',
    '## Evidence Index',
    evidenceIds || '- none',
    '',
    '## Cleanup Confirmation',
    cleanup,
    '',
    '## Review Boundary',
    'Any anomaly is a candidate for human validation only. This document does not generate a severity or submission decision.',
    ''
  ].join('\n');
}

export function renderReproduction(bundle: VerifiedEvidenceBundle): string {
  assertBundleShape(bundle);
  const operations = bundle.plan.operations
    .filter((operation) => operation.phase !== 'cleanup')
    .map((operation, index) => `${index + 1}. ${String.fromCharCode(96)}aegishub bounty execute --operation-id ${operation.operationId} --actor ${operation.actor} --step ${operation.stepId}${String.fromCharCode(96)}`)
    .join('\n');

  return [
    '# Sanitized reproduction procedure',
    '',
    `This procedure references only the reviewed catalog for experiment \`${bundle.experiment.id}\`.`,
    '',
    '## Preconditions',
    `- Use run \`${bundle.runId}\` with an already verified lab.`,
    `- Confirm policy version \`${bundle.policy.policyVersion}\` is current.`,
    '- Obtain the required interactive approval through the CLI; do not paste credentials into the procedure.',
    '',
    '## Catalog steps',
    operations || '- none',
    '',
    '## Interpretation',
    `Compare the sanitized evidence IDs in report.md with the expected result: ${bundle.experiment.expectedSafeOutcome}`,
    '',
    'This file intentionally omits raw HTTP, arbitrary URLs, cookies, authorization headers, request bodies, and shell interpolation.',
    ''
  ].join('\n');
}

function assertBundleShape(bundle: VerifiedEvidenceBundle): void {
  if (bundle.manifest.runId !== bundle.runId || bundle.diff.runId !== bundle.runId || bundle.experiment.id !== bundle.manifest.experimentId) {
    throw new Error('invalid_evidence_bundle');
  }
  if (bundle.manifest.result === 'anomalous' && bundle.candidate === undefined) throw new Error('invalid_evidence_bundle');
  if (bundle.manifest.result !== 'anomalous' && bundle.candidate !== undefined) throw new Error('invalid_evidence_bundle');
}
