import rsasign from 'jsrsasign'
import {Key, publicKeyToString} from 'zswjs/dist/zswjs-numeric'
const rs : any = rsasign;

const SM2_BIT_SIZE = 256
const SM2_SIGN_ALG = 'SM3withSM2'

const SM2_CURVE_NAME = 'sm2p256v1'
const SM2_CURVE_PARAM_P = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF'
const SM2_CURVE_PARAM_A = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC'
const SM2_CURVE_PARAM_B = '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'
const SM2_CURVE_PARAM_N = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123'
const SM2_CURVE_PARAM_GX = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'
const SM2_CURVE_PARAM_GY = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'

rs.crypto.ECParameterDB.regist(
  SM2_CURVE_NAME, // name / p = 2**256 - 2**224 - 2**96 + 2**64 - 1
  SM2_BIT_SIZE,
  SM2_CURVE_PARAM_P, // p
  SM2_CURVE_PARAM_A, // a
  SM2_CURVE_PARAM_B, // b
  SM2_CURVE_PARAM_N, // n
  '1', // h
  SM2_CURVE_PARAM_GX, // gx
  SM2_CURVE_PARAM_GY, // gy
  []) // alias

const getNameFunc = rs.ECDSA.getName
rs.ECDSA.getName = function (s: string) {
  // {1, 2, 156, 10197, 1, 301}
  if (s === '2a811ccf5501822d') {
    return SM2_CURVE_NAME
  }
  return getNameFunc(s)
}

rs.asn1.x509.OID.name2oidList[SM2_SIGN_ALG] = '1.2.156.10197.1.501'
rs.asn1.x509.OID.name2oidList[SM2_CURVE_NAME] = '1.2.156.10197.1.301'

function sm2PemToXYHex(pemString: string): {x: string, y: string}{
  return rs.KEYUTIL.getKey(pemString).getPublicKeyXYHex();
}
function sm2PemToKey(pemString: string): Key {
  const hexPoint = sm2PemToXYHex(pemString);
  const x = Buffer.from(hexPoint.x, 'hex');
  const y = Buffer.from(hexPoint.y, 'hex');
  return {
    type: 3,
    data: Buffer.concat([
      new Uint8Array([(y[31] & 1) ? 3 : 2]),
      x,
    ]),
  };
}
function sm2PemToKeyString(pemString: string): string {
  return publicKeyToString(sm2PemToKey(pemString));
}

export {
  sm2PemToXYHex,
  sm2PemToKey,
  sm2PemToKeyString,
}