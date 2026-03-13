/**
 * Cross-package tree-shaking test for @solana/keychain (umbrella package).
 *
 * Verifies that importing a single signer factory from the umbrella package
 * does NOT pull in code from other signer packages. Uses Rollup to perform
 * real tree-shaking with workspace packages resolved.
 *
 * Usage: node scripts/test-treeshake-umbrella.mjs
 */

import { rollup } from 'rollup';
import nodeResolve from '@rollup/plugin-node-resolve';
import virtual from '@rollup/plugin-virtual';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packagesDir = path.join(__dirname, '..', 'packages');

// Each entry: [importName, uniqueStringsFromOtherSigners]
// We import ONE factory and verify that marker strings from OTHER signers are absent.
const SIGNER_MARKERS = {
    'aws-kms': ['KMSClient', 'aws-sdk'],
    cdp: ['cdp.coinbase.com', 'CDP_BASE_PATH'],
    crossmint: ['crossmint.com/api', 'Crossmint transaction polling timed out'],
    dfns: ['api.dfns.io', 'signUserAction'],
    fireblocks: ['api.fireblocks.io', 'PENDING_SIGNATURE'],
    'gcp-kms': ['KeyManagementServiceClient', 'google-cloud'],
    para: ['para-signer', 'UUID_REGEX'],
    privy: ['api.privy.io', 'privy-app-id'],
    turnkey: ['api.turnkey.com', 'X-Stamp'],
    vault: ['transit/sign', 'vault-signer'],
};

const FACTORIES = [
    { name: 'createAwsKmsSigner', pkg: 'aws-kms' },
    { name: 'createCdpSigner', pkg: 'cdp' },
    { name: 'createCrossmintSigner', pkg: 'crossmint' },
    { name: 'createDfnsSigner', pkg: 'dfns' },
    { name: 'createFireblocksSigner', pkg: 'fireblocks' },
    { name: 'createGcpKmsSigner', pkg: 'gcp-kms' },
    { name: 'createParaSigner', pkg: 'para' },
    { name: 'createPrivySigner', pkg: 'privy' },
    { name: 'createTurnkeySigner', pkg: 'turnkey' },
    { name: 'createVaultSigner', pkg: 'vault' },
];

async function bundleImport(importName) {
    const keychainDist = path.join(packagesDir, 'keychain', 'dist', 'index.js');

    const bundle = await rollup({
        input: '__test__',
        plugins: [
            virtual({
                __test__: `export { ${importName} } from ${JSON.stringify(keychainDist)}`,
            }),
            nodeResolve({
                // Resolve workspace packages from their dist/ folders
                rootDir: path.join(__dirname, '..'),
            }),
        ],
        // Mark everything that isn't a workspace package as external
        external: (id) => {
            if (id === '__test__') return false;
            if (id.startsWith('/') || id.startsWith('.')) return false;
            if (id.startsWith('@solana/keychain')) return false;
            return true;
        },
        onwarn: () => {},
    });

    const result = await bundle.generate({ format: 'esm' });
    await bundle.close();
    return result.output[0].code;
}

let failures = 0;

for (const factory of FACTORIES) {
    const code = await bundleImport(factory.name);

    // Check that OTHER signers' marker strings don't appear
    const otherSigners = Object.entries(SIGNER_MARKERS).filter(([pkg]) => pkg !== factory.pkg);

    for (const [otherPkg, markers] of otherSigners) {
        for (const marker of markers) {
            if (code.includes(marker)) {
                console.error(
                    `FAIL: import { ${factory.name} } from '@solana/keychain' includes code from ${otherPkg} (found "${marker}")`,
                );
                failures++;
                break; // one marker per package is enough
            }
        }
    }
}

if (failures === 0) {
    console.log(
        `OK: All ${FACTORIES.length} signer factories tree-shake cleanly — importing one does not pull in others.`,
    );
    process.exit(0);
} else {
    console.error(`\n${failures} cross-package tree-shake failure(s)`);
    process.exit(1);
}
