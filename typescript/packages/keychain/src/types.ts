import type { AwsKmsSignerConfig } from '@solana/keychain-aws-kms';
import type { CdpSignerConfig } from '@solana/keychain-cdp';
import type { CrossmintSignerConfig } from '@solana/keychain-crossmint';
import type { DfnsSignerConfig } from '@solana/keychain-dfns';
import type { FireblocksSignerConfig } from '@solana/keychain-fireblocks';
import type { GcpKmsSignerConfig } from '@solana/keychain-gcp-kms';
import type { ParaSignerConfig } from '@solana/keychain-para';
import type { PrivySignerConfig } from '@solana/keychain-privy';
import type { TurnkeySignerConfig } from '@solana/keychain-turnkey';
import type { VaultSignerConfig } from '@solana/keychain-vault';

/**
 * Discriminated union of all signer backend configurations.
 * The `backend` field narrows the type to the correct config shape.
 */
export type KeychainSignerConfig =
    | (AwsKmsSignerConfig & { backend: 'aws-kms' })
    | (CdpSignerConfig & { backend: 'cdp' })
    | (CrossmintSignerConfig & { backend: 'crossmint' })
    | (DfnsSignerConfig & { backend: 'dfns' })
    | (FireblocksSignerConfig & { backend: 'fireblocks' })
    | (GcpKmsSignerConfig & { backend: 'gcp-kms' })
    | (ParaSignerConfig & { backend: 'para' })
    | (PrivySignerConfig & { backend: 'privy' })
    | (TurnkeySignerConfig & { backend: 'turnkey' })
    | (VaultSignerConfig & { backend: 'vault' });

/** String literal union of all supported backend names, derived from {@link KeychainSignerConfig}. */
export type BackendName = KeychainSignerConfig['backend'];
