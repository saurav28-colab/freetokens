import { describe, expect, it } from 'vitest';
import { AUTH_JSON_PROVIDER_MAP, detectPlatform } from '../../lib/key-parser.js';
import { getProvider, hasProvider } from '../../providers/index.js';

describe('Token Harbor provider registration', () => {
  it('registers the documented OpenAI-compatible base URL', () => {
    expect(hasProvider('tokenharbor')).toBe(true);
    const provider = getProvider('tokenharbor');

    expect(provider).toBeDefined();
    expect(provider?.platform).toBe('tokenharbor');
    expect((provider as { baseUrl?: string }).baseUrl).toBe('https://tokenharbor.ai/v1');
  });

  it.each(['TOKENHARBOR_', 'TOKEN_HARBOR_'])('resolves the %s environment prefix', (prefix) => {
    expect(detectPlatform(prefix)).toBe('tokenharbor');
  });

  it.each(['tokenharbor', 'token-harbor'])('resolves the %s auth.json provider name', (providerName) => {
    expect(AUTH_JSON_PROVIDER_MAP[providerName]).toBe('tokenharbor');
  });
});
