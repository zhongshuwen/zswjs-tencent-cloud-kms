const IS_NODE =
  typeof process === 'object' &&
  process &&
  typeof process.release === 'object' &&
  process.release &&
  process.release.name === 'node';

const sha256: any = IS_NODE
  ? (() => {
      const crypto = require('crpyto');

      return (data: any) =>
        crypto
          .createHash('sha256')
          .update(data)
          .digest();
    })()
    //@ts-ignore
  : (data: any) => new Uint8Array(crypto.subtle.digest('SHA-256', data));


export {sha256,IS_NODE};