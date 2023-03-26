const crypto = require("crypto");

const ENCKEY = "secure-enckey-string";
const TEXT =
  "Dolor minim ad ad magna adipisicing eiusmod. Irure elit anim aute cillum ullamco esse do sunt laborum quis. Non adipisicing anim proident ad velit laboris do pariatur. Amet duis elit magna nulla exercitation commodo sint excepteur aliquip minim ea sit reprehenderit ad. Sunt in cupidatat fugiat Lorem. Et minim elit incididunt nisi magna enim deserunt exercitation fugiat aute non. Quis non enim commodo officia velit et aliqua excepteur ad sit non amet.";

function encrypt(plaintext) {
  // random iv
  const iv = crypto.randomBytes(16);

  // random salt
  const salt = crypto.randomBytes(64);

  // derive key: 32 byte key length - in assumption the masterkey is a cryptographic and NOT a password there is no need for
  // a large number of iterations. It may can replaced by HKDF
  const key = crypto.pbkdf2Sync(ENCKEY, salt, 2145, 32, "sha512");

  // AES 256 GCM Mode
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);

  // encrypt the given text
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);

  return Buffer.concat([salt, iv, encrypted]).toString("base64");
}

function decrypt(ciphertext) {
  // base64 decoding
  var bData = Buffer.from(ciphertext, "base64");

  // convert data to buffers
  var salt = bData.slice(0, 64);
  var iv = bData.slice(64, 80);
  var text = bData.slice(80);

  // derive key using; 32 byte key length
  var key = crypto.pbkdf2Sync(ENCKEY, salt, 2145, 32, "sha512");

  // AES 256 GCM Mode
  var decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);

  return decipher.update(text, "binary", "utf8") + decipher.final("utf8");
}

const encrypted = encrypt(TEXT);
const decrypted = decrypt(encrypted);

console.log("encrypted:", encrypted);
console.log("decrypted:", decrypted);
