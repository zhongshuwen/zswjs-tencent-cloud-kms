/**
 * @module KMSSig
 */
// copyright defined in zswjs/LICENSE.txt

import type { SignatureProvider, SignatureProviderArgs } from 'zswjs/dist/zswjs-api-interfaces';
import type { PushTransactionArgs } from 'zswjs/dist/zswjs-rpc-interfaces';
import * as ser from 'zswjs/dist/zswjs-serialize';
import * as numeric from 'zswjs/dist/zswjs-numeric';
import type {ClientConfig} from 'tencentcloud-sdk-nodejs/tencentcloud/common/interface';
import { getZSWPublicKeyStringForTencentKMSKeyId, signDigestTencentKMS } from './apiHelper';
import { sha256, IS_NODE } from '../util';
interface KeyProviderCachedKey {
    ZswChainPublicKeyString: string;
    KeyId: string;
    KeyVersionId?: string;
    CacheExpireTime: number;
}
/** Signs transactions using WebAuthn */
export class TencentCloudKMSignatureProvider implements SignatureProvider {

    /** Map public key to credential ID (hex). User must populate this. */
    private keyToIdCache = new Map<string, KeyProviderCachedKey>();
    private unprocessedKeys : Set<string>;
    private clientConfig : ClientConfig;
    private keyCacheTime : number;
    constructor(inClientConfig: ClientConfig, keyIds: string[] = [], keyCacheTime: number = -1){
        this.clientConfig = inClientConfig;
        if(!this.clientConfig.profile){
            this.clientConfig.profile = {};
        }
        this.unprocessedKeys = new Set(keyIds);
        this.keyCacheTime = keyCacheTime;
    }

    public async addKeyByIdToCache(keyId: string){
        const zswPublicKeyString = await getZSWPublicKeyStringForTencentKMSKeyId(this.clientConfig, keyId);
        this.keyToIdCache.set(zswPublicKeyString, <KeyProviderCachedKey>{
            KeyId: keyId,
            ZswChainPublicKeyString: zswPublicKeyString,
            CacheExpireTime: Date.now() + this.keyCacheTime,
        });
    }
    public addKeyById(keyId: string){
        this.unprocessedKeys.add(keyId);
    }

    /** Public keys that the `SignatureProvider` holds */
    public async getAvailableKeys(): Promise<string[]> {
        if(this.keyCacheTime === 0){
            const values = this.keyToIdCache.values();
            this.keyToIdCache = new Map<string, KeyProviderCachedKey>();
            for(let v in values){
                this.unprocessedKeys.add(v);
            }
        }

        const unprocessedKeysArray = Array.from(this.unprocessedKeys);
        for(let upk of unprocessedKeysArray){
            await this.addKeyByIdToCache(upk);
        }
        return Array.from(this.keyToIdCache.keys());
    }

    /** Sign a transaction */
    public async sign(
        { chainId, requiredKeys, serializedTransaction, serializedContextFreeData }: SignatureProviderArgs,
    ): Promise<PushTransactionArgs> {
        const signBuf = new ser.SerialBuffer();
        signBuf.pushArray(ser.hexToUint8Array(chainId));
        signBuf.pushArray(serializedTransaction);
        if (serializedContextFreeData) {
            if(IS_NODE){

                signBuf.pushArray(sha256(serializedContextFreeData));
            }else{

            signBuf.pushArray(await sha256(serializedContextFreeData));
            }
        } else {
            signBuf.pushArray(new Uint8Array(32));
        }
        
        const digest =IS_NODE? sha256(signBuf.asUint8Array().slice()):(await sha256(signBuf.asUint8Array().slice()));

        const signatures = [] as string[];
        for (const key of requiredKeys) {
            const keyDef = this.keyToIdCache.get(key);
            if(!keyDef){
                throw new Error("Missing key "+key);
            }
            const signatureResponseBase64 = await signDigestTencentKMS(this.clientConfig, keyDef.KeyId, Buffer.from(digest).toString('base64'));
            const resultBuffer = Buffer.alloc(105);
            resultBuffer.set(numeric.stringToPublicKey(keyDef.ZswChainPublicKeyString).data, 0);
            resultBuffer.set(Buffer.from(signatureResponseBase64, 'base64'),33);
            const sig = numeric.signatureToString({
                type: numeric.KeyType.gm,
                data: resultBuffer.slice(),
            });
            signatures.push(sig);
        }
        return { signatures, serializedTransaction, serializedContextFreeData };
    }
}
