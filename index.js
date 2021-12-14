const crypto = require('crypto');
const bs58 = require('bs58')
const btoa = require('btoa');
const atob = require('atob');

const OFFSET = 128;

// Generate Private Key
const secretEd25519 = crypto.generateKeyPairSync('ed25519', {
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'der',
  }
}).privateKey.toString('base64');
const secretRsa = crypto.generateKeyPairSync('rsa', {
  modulusLength: 4096,
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'der',
  }
}).privateKey.toString('base64');
console.log(`secretEd25519: ${secretEd25519}`);
// console.log(`secretRsa: ${secretRsa}`);

const cid1 = '1111111111111';
const cid2 = '2222222222222';

const salt = crypto.randomBytes(32).toString('base64');
console.log(`salt: ${salt}\n`);

// Generate base58 PIN from Private Key & Salt
const pinEd25519 = bs58.encode(crypto
                                .createHash('sha256')
                                .update(secretEd25519.concat(salt))
                                .digest())
                    .substring(0, 6);
const pinRsa = bs58.encode(crypto
                                .createHash('sha256')
                                .update(secretRsa.concat(salt))
                                .digest())
                    .substring(0, 6);
console.log(`pinEd25519: ${pinEd25519}`)
// console.log(`pinRsa: ${pinRsa}\n`)

// Create Sub Share
// Modified Polynomial Equation: 2 shares (cid, share) -> Linear
// x = 0: Private Key
// x = 1: Citizen ID
// x = 2: Share
const createSubShares = (subSecret, subCid) =>
                          [1,2].map((x) =>
                            ((x) * (subCid - subSecret)) + subSecret);

// Create Share from Private Key & CID
// Calculate Share digit by digit
const createShares = (secret, cid) => {
  const subSecrets = Buffer.from(secret, 'base64').toString('hex').split('');
  const subShares = subSecrets.map((s, index) => {
                      const [, share] = createSubShares(parseInt(s, 16), +(cid[index % cid.length]))
                      return String.fromCharCode(share + OFFSET); // convert to positive value, TODO: find others solution?
                    });

  return btoa(subShares.join(''));
}

// Generate Private Key from CID & share
const recoverSecret = (cid, share) => {
  const subShares = atob(share).split('')
  const key = subShares.map((s, index) =>
                ((+(cid[index  % cid.length]) * 2) + ((s.charCodeAt() - OFFSET) * (-1)))
                  .toString(16));

  return Buffer.from(key.join(''), 'hex').toString('base64');
}

///////////////////////// Test ED25519 //////////////////////////////
const share1 = createShares(secretEd25519, cid1);
const share2 = createShares(secretEd25519, cid2);
console.log(`share1: ${share1}`);
// console.log(`share2: ${share2}\n`);

const recoverSecret1 = recoverSecret(cid1, share1);
const recoverSecret2 = recoverSecret(cid2, share2);
// console.log(`recoverSecret1: ${recoverSecret1}`);
// console.log(`recoverSecret2: ${recoverSecret2}\n`);

console.log('recoverSecret ED25519 match: ',
  (secretEd25519 === recoverSecret1) && (secretEd25519 === recoverSecret2));
//////////////////////////////////////////////////////////////////////

///////////////////////// Test RSA 4096 //////////////////////////////
const share3 = createShares(secretRsa, cid1);
const share4 = createShares(secretRsa, cid2);
// console.log(`share3: ${share3}`);
// console.log(`share4: ${share4}\n`);

const recoverSecret3 = recoverSecret(cid1, share3);
const recoverSecret4 = recoverSecret(cid2, share4);
// console.log(`recoverSecret3: ${recoverSecret3}`);
// console.log(`recoverSecret4: ${recoverSecret4}\n`);

// console.log('recoverSecret RSA match: ',
//   (secretRsa === recoverSecret3) && (secretRsa === recoverSecret4));
////////////////////////////////////////////////////////////////////
