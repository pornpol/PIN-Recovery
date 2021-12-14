const crypto = require('crypto');
const bs58 = require('bs58')
const btoa = require('btoa');
const atob = require('atob');

const OFFSET = 128;

const key = crypto.randomBytes(32).toString('base64');
console.log(`key: ${key}\n`);

const cid1 = '1111111111111';
const cid2 = '2222222222222';

const salt = crypto.randomBytes(32).toString('base64');
console.log(`salt: ${salt}\n`);

// Generate base58 PIN from Key & Salt

const pin = bs58.encode(crypto
                          .createHash('sha256')
                          .update(key.concat(salt))
                          .digest())
              .substring(0, 6);
console.log(`pin: ${pin}\n`)

// Create Sub Share
// Modified Polynomial Equation: 2 shares (cid, share) -> Linear
// x = 0: Key
// x = 1: Citizen ID
// x = 2: Share
const createSubShares = (subSecret, subCid) =>
                          [1,2].map((x) =>
                            ((x) * (subCid - subSecret)) + subSecret);

// Create Share from Key & CID
// Calculate Share digit by digit
const createShares = (secret, cid) => {
  const subSecrets = Buffer.from(secret, 'base64').toString('hex').split('');
  const subShares = subSecrets.map((s, index) => {
                      const [, share] = createSubShares(parseInt(s, 16), +(cid[index % cid.length]))
                      return String.fromCharCode(share + OFFSET); // convert to positive value, TODO: find others solution?
                    });

  return btoa(subShares.join(''));
}

// Generate Key from CID & share
const recoverSecret = (cid, share) => {
  const subShares = atob(share).split('')
  const key = subShares.map((s, index) =>
                ((+(cid[index  % cid.length]) * 2) + ((s.charCodeAt() - OFFSET) * (-1)))
                  .toString(16));

  return Buffer.from(key.join(''), 'hex').toString('base64');
}

///////////////////////// Test ED25519 //////////////////////////////
const share1 = createShares(key, cid1);
const share2 = createShares(key, cid2);
console.log(`share1: ${share1}`);
console.log(`share2: ${share2}\n`);

const recoverSecret1 = recoverSecret(cid1, share1);
const recoverSecret2 = recoverSecret(cid2, share2);
console.log(`recoverSecret1: ${recoverSecret1}`);
console.log(`recoverSecret2: ${recoverSecret2}\n`);

console.log('recoverSecret match: ',
  (key === recoverSecret1) && (key === recoverSecret2));
//////////////////////////////////////////////////////////////////////
