import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ALLOWED_COMPLETION_CALLBACK,
  buildCompletionEvent,
  getCompletionCallback,
  postCompletion,
} from '../dist/completion-callback.js';

test('completion callback is disabled unless the fixed integration is selected', () => {
  assert.equal(getCompletionCallback({}), null);
  assert.equal(
    getCompletionCallback({ SSS_HUMAN_REQUEST_CALLBACK: 'agent-herder' }),
    ALLOWED_COMPLETION_CALLBACK,
  );
  assert.throws(
    () => getCompletionCallback({ SSS_HUMAN_REQUEST_CALLBACK: 'https://attacker.example/callback' }),
    /unsupported callback configuration/,
  );
});

test('completion event contains only opaque correlation metadata', () => {
  const event = buildCompletionEvent('7f6f1f71-a12c-4f4e-b7a1-8e6883b2cae1', '4a6f5e3c-83b4-4d3c-9f8e-5a7f9a0d88a1');
  assert.deepEqual(event, {
    event: 'sss.secret_input.completed',
    event_version: 1,
    request_id: '7f6f1f71-a12c-4f4e-b7a1-8e6883b2cae1',
    status: 'completed',
    result_ref: '4a6f5e3c-83b4-4d3c-9f8e-5a7f9a0d88a1',
  });
  assert.equal('value' in event, false);
  assert.equal('secret' in event, false);
  assert.equal('token' in event, false);
});

test('callback POST uses the fixed URL and never changes completion outcome', async () => {
  const calls = [];
  await postCompletion(ALLOWED_COMPLETION_CALLBACK, buildCompletionEvent(
    '7f6f1f71-a12c-4f4e-b7a1-8e6883b2cae1',
    '4a6f5e3c-83b4-4d3c-9f8e-5a7f9a0d88a1',
  ), async (url, options) => {
    calls.push({ url, options });
    return { ok: true };
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, ALLOWED_COMPLETION_CALLBACK);
  assert.equal(calls[0].options.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].options.body), {
    event: 'sss.secret_input.completed',
    event_version: 1,
    request_id: '7f6f1f71-a12c-4f4e-b7a1-8e6883b2cae1',
    status: 'completed',
    result_ref: '4a6f5e3c-83b4-4d3c-9f8e-5a7f9a0d88a1',
  });
});

test('callback delivery errors are isolated from SSS completion', async () => {
  await assert.doesNotReject(() => postCompletion(
    ALLOWED_COMPLETION_CALLBACK,
    buildCompletionEvent('7f6f1f71-a12c-4f4e-b7a1-8e6883b2cae1', '4a6f5e3c-83b4-4d3c-9f8e-5a7f9a0d88a1'),
    async () => { throw new Error('callback unavailable'); },
  ));
});
