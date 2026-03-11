import type { SerializedError } from 'vitest';
import type { Reporter, TestModule, TestRunEndReason } from 'vitest/node';

/**
 * Custom vitest reporter that fails CI when all tests in a module are skipped.
 *
 * This catches the scenario where CI secrets are accidentally removed —
 * integration tests silently skip via `it.skipIf()` and vitest reports
 * a green build with "N skipped, 0 failed".
 *
 * Only active when CI=true. Individual skips (e.g. Fireblocks RAW mode)
 * are allowed as long as at least one test in the module executes.
 *
 * Note: vitest swallows reporter exceptions (try-catch internally), so
 * this method wraps all logic in try-catch to ensure any unexpected error
 * still results in a non-zero exit.
 */
export default class NoAllSkippedReporter implements Reporter {
    onTestRunEnd(
        testModules: ReadonlyArray<TestModule>,
        unhandledErrors: ReadonlyArray<SerializedError>,
        _reason: TestRunEndReason,
    ) {
        if (!process.env.CI) return;

        try {
            if (unhandledErrors.length > 0) {
                console.error(`\nCI FAILURE: ${unhandledErrors.length} unhandled error(s) during test run.\n`);
                process.exitCode = 1;
                process.exit(1);
            }

            if (testModules.length === 0) {
                console.error(
                    '\nCI FAILURE: No test modules were collected.\n' +
                        'This may indicate a configuration or import error.\n',
                );
                process.exitCode = 1;
                process.exit(1);
            }

            const allSkippedModules: string[] = [];

            for (const mod of testModules) {
                const allTests = [...mod.children.allTests()];
                if (allTests.length === 0) continue;

                const hasExecuted = allTests.some(t => {
                    const state = t.result()?.state;
                    return state === 'passed' || state === 'failed';
                });

                if (!hasExecuted) {
                    allSkippedModules.push(mod.moduleId);
                }
            }

            if (allSkippedModules.length > 0) {
                const filenames = allSkippedModules.map(f => `  - ${f}`).join('\n');
                console.error(
                    `\nCI FAILURE: All tests were skipped in:\n${filenames}\n` +
                        'Required secrets may be missing from CI configuration.\n',
                );
                process.exitCode = 1;
                process.exit(1);
            }
        } catch (err) {
            console.error('\nCI FAILURE: NoAllSkippedReporter encountered an unexpected error:\n', err, '\n');
            process.exitCode = 1;
            process.exit(1);
        }
    }
}
