import { mkdtemp, readFile, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  JournalError,
  WriteAheadMutationJournal,
  type JournalMutationEntry
} from '../src/experiments/journal.js';

const timestamp = '2026-08-13T12:00:00.000Z';

function entry(overrides: Partial<JournalMutationEntry> = {}): JournalMutationEntry {
  return {
    entryId: 'mutation-1',
    kind: 'experiment-mutation',
    repositoryId: 3003,
    operationOrdinal: 1,
    catalogId: 'github.rest.put-lab-marker',
    parametersSha256: 'a'.repeat(64),
    inverseOperationId: 'github.rest.delete-lab-marker',
    ...overrides
  };
}

async function createJournal() {
  const workspace = await mkdtemp(join(tmpdir(), 'aegishub-journal-'));
  return {
    workspace,
    journal: await WriteAheadMutationJournal.create({
      workspaceRoot: workspace,
      runId: '3e7b5d2e-6a5f-4e9c-a0e5-9ce8fef35e12',
      planFingerprint: 'b'.repeat(64),
      now: () => new Date(timestamp)
    })
  };
}

describe('WriteAheadMutationJournal', () => {
  it('allows the complete verified cleanup state machine and flushes every append', async () => {
    const { journal } = await createJournal();

    await journal.prepare(entry());
    await journal.markSent('mutation-1');
    await journal.markObserved('mutation-1', 'evidence-observed');
    await journal.markVerifiedApplied('mutation-1', 'evidence-applied');
    await journal.markCleanupSent('mutation-1');
    await journal.markClean('mutation-1', 'evidence-clean');

    expect(journal.state('mutation-1')).toBe('clean');
    expect(journal.records()).toHaveLength(6);
    const serialized = await readFile(journal.path(), 'utf8');
    expect(serialized.endsWith('\n')).toBe(true);
    expect(serialized).not.toContain('controlNonce');
    expect(serialized).not.toContain('rawRequest');
    expect(serialized).not.toContain('rawResponse');
  });

  it('reopens interleaved mutation entries and validates each entry state independently', async () => {
    const { journal } = await createJournal();
    await journal.prepare(entry());
    await journal.prepare(entry({ entryId: 'mutation-2', operationOrdinal: 2 }));
    await journal.markSent('mutation-1');
    await journal.markSent('mutation-2');

    const reopened = await WriteAheadMutationJournal.open({
      workspaceRoot: journal.workspaceRoot(),
      runId: journal.runId(),
      planFingerprint: 'b'.repeat(64)
    });
    expect(reopened.state('mutation-1')).toBe('sent');
    expect(reopened.state('mutation-2')).toBe('sent');
  });

  it('supports unknown mutation outcomes and rejects skipped, duplicated, and terminal transitions', async () => {
    const { journal } = await createJournal();

    await expect(journal.markSent('missing')).rejects.toMatchObject({ code: 'journal_entry_missing' });
    await journal.prepare(entry());
    await expect(journal.markVerifiedApplied('mutation-1', 'evidence')).rejects.toMatchObject({ code: 'journal_invalid_transition' });
    await journal.markSent('mutation-1');
    await journal.markOutcomeUnknown('mutation-1');
    await journal.markVerifiedNotApplied('mutation-1', 'evidence-not-applied');
    await journal.markClean('mutation-1', 'evidence-clean');
    await expect(journal.markClean('mutation-1', 'evidence-clean')).rejects.toMatchObject({ code: 'journal_invalid_transition' });
    await expect(journal.markSent('mutation-1')).rejects.toMatchObject({ code: 'journal_invalid_transition' });
  });

  it('rejects altered and truncated hash chains when reopening', async () => {
    const { journal } = await createJournal();
    await journal.prepare(entry());
    await journal.markSent('mutation-1');

    const path = journal.path();
    const original = await readFile(path, 'utf8');
    const altered = original.replace('"mutationState":"sent"', '"mutationState":"observed"');
    await writeFile(path, altered, 'utf8');
    await expect(WriteAheadMutationJournal.open({
      workspaceRoot: journal.workspaceRoot(),
      runId: journal.runId(),
      planFingerprint: 'b'.repeat(64)
    })).rejects.toMatchObject({ code: 'journal_chain_invalid' });

    await writeFile(path, original, 'utf8');
    await truncate(path, original.lastIndexOf('\n'));
    await expect(WriteAheadMutationJournal.open({
      workspaceRoot: journal.workspaceRoot(),
      runId: journal.runId(),
      planFingerprint: 'b'.repeat(64)
    })).rejects.toMatchObject({ code: 'journal_chain_invalid' });
  });

  it('accepts the LabVerifier configuration mutation shape through the same primitive', async () => {
    const { journal } = await createJournal();
    await journal.prepare({
      entryId: 'lab-entry',
      kind: 'lab-marker-create',
      repositoryId: 3003,
      inverse: 'delete-marker'
    });
    await journal.markSent('lab-entry');
    await journal.markVerified('lab-entry');

    await journal.prepare({
      entryId: 'lab-entry-rollback',
      kind: 'lab-marker-create',
      repositoryId: 3003,
      inverse: 'delete-marker'
    });
    await journal.markRolledBack('lab-entry-rollback');

    expect(journal.state('lab-entry')).toBe('verified-retained');
    expect(journal.state('lab-entry-rollback')).toBe('rolled-back');
  });

  it('exposes stable errors for invalid state transitions', async () => {
    const { journal } = await createJournal();
    await expect(journal.markDirty('missing', 'reason')).rejects.toEqual(new JournalError('journal_entry_missing'));
  });
});

export { timestamp };
