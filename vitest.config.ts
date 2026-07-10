import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Forked child processes allow process.chdir(), which the uninstall
    // tests use to exercise the cwd-based helper inside throwaway fixtures.
    pool: 'forks',
  },
});
