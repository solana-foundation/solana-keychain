import type { SolanaSigner } from '@solana/keychain-core';
import { SignerTestConfig, TestScenario } from '@solana/keychain-test-utils';
import { createDfnsSigner } from '../dfns-signer.js';

export const TEST_AUTH_TOKEN = 'test-auth-token';
export const TEST_CRED_ID = 'test-cred-id';
export const TEST_WALLET_ID = 'test-wallet-id';
export const TEST_KEY_ID = 'test-key-id';

// Ed25519 test key in PKCS#8 PEM format
export const TEST_ED25519_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikUmifl1yiWd+IiYyoHBD
-----END PRIVATE KEY-----`;

export const TEST_PUBKEY_HEX = '5da30b28c87836b0ee76ae7b07e3a2e3be1a4c12e48fce3aee18de0a13040b9a';

export function createWalletResponse(overrides?: Partial<{ status: string; scheme: string; curve: string }>) {
    return {
        id: TEST_WALLET_ID,
        network: 'Solana',
        signingKey: {
            id: TEST_KEY_ID,
            curve: overrides?.curve ?? 'ed25519',
            publicKey: TEST_PUBKEY_HEX,
            scheme: overrides?.scheme ?? 'EdDSA',
        },
        status: overrides?.status ?? 'Active',
    };
}

export function createUserActionInitResponse() {
    return {
        allowCredentials: {
            key: [{ id: TEST_CRED_ID }],
        },
        challenge: 'test-challenge',
        challengeIdentifier: 'test-challenge-id',
    };
}

export function createUserActionResponse() {
    return {
        userAction: 'test-user-action-token',
    };
}

export function createSignatureResponse(r: string, s: string) {
    return {
        id: 'sig-123',
        signature: { r, s },
        status: 'Signed',
    };
}

const SIGNER_TYPE = 'dfns';
const REQUIRED_ENV_VARS = ['DFNS_AUTH_TOKEN', 'DFNS_CRED_ID', 'DFNS_PRIVATE_KEY_PEM', 'DFNS_WALLET_ID'];

const CONFIG: SignerTestConfig<SolanaSigner> = {
    signerType: SIGNER_TYPE,
    requiredEnvVars: REQUIRED_ENV_VARS,
    createSigner: () =>
        createDfnsSigner({
            authToken: process.env.DFNS_AUTH_TOKEN!,
            credId: process.env.DFNS_CRED_ID!,
            privateKeyPem: process.env.DFNS_PRIVATE_KEY_PEM!,
            walletId: process.env.DFNS_WALLET_ID!,
            apiBaseUrl: process.env.DFNS_API_BASE_URL,
        }),
};

export async function getConfig(scenarios: TestScenario[]): Promise<SignerTestConfig<SolanaSigner>> {
    return {
        ...CONFIG,
        testScenarios: scenarios,
    };
}
