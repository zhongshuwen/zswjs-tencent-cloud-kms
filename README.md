# zswjs-tencent-cloud-kms
## 中数文联盟链JS SDK - 腾讯云KMS密钥管理系统Plugin


## Usage
```js
const zswjs = require("zswjs");
const { TencentCloudKMSignatureProvider } = require("zswjs-tencent-cloud-kms");

function signTransactionDemo() {
  
  const rpc = new JsonRpc('http://127.0.0.1:8888', { fetch });
  const clientConfig = {
    credential: {
      secretId: "<your-secret-id>",
      secretKey: "<your-secret-key>",
    }
    region: "<your-region", // example: "ap-shanghai"
  };
  const signatureProvider = new TencentCloudKMSignatureProvider(clientConfig, [
    "<key-id>",
  ])
  const api = new Api({ rpc, signatureProvider, textDecoder: new TextDecoder(), textEncoder: new TextEncoder() });
}
```
