const crypto = require('crypto');
const bs58 = require('bs58')
const btoa = require('btoa');
const atob = require('atob');

const key = crypto.randomBytes(32).toString('base64');
console.log(`key: ${key}\n`);

const cid1 = '1204565412398';
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
const createSubShares = (subSecret, cid) =>
                          [1,2].map((x) =>
                            ((x) * (cid - subSecret)) + subSecret); 

// Create Share from Key & CID
// Calculate Share digit by digit
const createShares = (secret, cid) => {
  const secretsHex = Buffer.from(secret, 'base64').toString('hex');
  const subSecretsHex = secretsHex.match(/.{1,8}/g); // split to 8 digits array

  const subShares = subSecretsHex.map((s, index) => {
    console.log(parseInt(s, 16));
    const [_, share] = createSubShares(parseInt(s, 16), cid)

    return btoa(share.toString(16)); // 8 hex string -> 16 base64 string
  });

  return subShares.join('');
}

// Generate Key from CID & share
const recoverSecret = (cid, share) => {
  const subShares = share.match(/.{1,16}/g) // 16 base64 string -> 8 hex string

  const key = subShares.map((s, index) => {
    let sHex = atob(s);
    let sInt = parseInt(sHex, 16);

    return ((cid * 2) + ((sInt) * (-1))).toString(16).padStart(8, '0');
  })

  return Buffer.from(key.join(''), 'hex').toString('base64');
}

///////////////////////// Test //////////////////////////////
const share1 = createShares(key, cid1);
const share2 = createShares(key, cid2);
console.log(`share1: ${share1}`);
console.log(`share2: ${share2}\n`);

const recoverSecret1 = recoverSecret(cid1, share1);
const recoverSecret2 = recoverSecret(cid2, share2);
console.log(`recoverSecret1: ${recoverSecret1}`);
console.log(`recoverSecret2: ${recoverSecret2}\n`);

console.log('recoverSecret match: ', (key === recoverSecret1) && (key === recoverSecret2));
//////////////////////////////////////////////////////////////////////