import type {ClientConfig} from 'tencentcloud-sdk-nodejs/tencentcloud/common/interface';
import {kms} from 'tencentcloud-sdk-nodejs/tencentcloud/services/kms';
import { sm2PemToKeyString } from '../gmpem';
const KmsClient = kms.v20190118.Client;

function getZSWPublicKeyStringForTencentKMSKeyId(clientConfig: ClientConfig, keyId: string): Promise<string> {
  const client = new KmsClient(clientConfig);
  const params = {
      "KeyId": keyId
  };
  return new Promise((resolve, reject)=>{
    client.GetPublicKey(params).then(
      (data) => {
        try {
          resolve(sm2PemToKeyString(data.PublicKeyPem));
        }catch(err){
          reject(err);
        }
      },
      (err) => {
        reject(err);
      }
    );
  })
}
async function signDigestTencentKMS(clientConfig: ClientConfig, keyId: string, digestBase64: string): Promise<string> {
  const client = new KmsClient(clientConfig);
  const signatureResponse = await client.SignByAsymmetricKey({
    Algorithm: "SM2DSA",
    Message: digestBase64,
    KeyId: keyId,
    MessageType: "DIGEST",
  })
  return signatureResponse.Signature;
}

export {
  getZSWPublicKeyStringForTencentKMSKeyId,
  signDigestTencentKMS,
}