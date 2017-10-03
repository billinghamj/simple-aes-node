import crypto from 'crypto';

const KEY_SYM = Symbol('key');
const BITS_IN_BYTE = 8;
const BLOCK_SIZE = 16; // 128 bits

export default class SimpleAES {
	cipher: string;
	[KEY_SYM]: Buffer;

	constructor(keyLength: 128|192|256, key: string|Buffer) {
		this.cipher = `aes${keyLength}`;
		this[KEY_SYM] = parseKey(key, keyLength / BITS_IN_BYTE);
	}

	encrypt(plaintext: string): { iv: string, ciphertext: string } {
		const ptBuf = Buffer.from(plaintext, 'utf8');
		const ivBuf = crypto.randomBytes(BLOCK_SIZE);

		const cipher = crypto.createCipheriv(this.cipher, this[KEY_SYM], ivBuf);

		const ctBuf = Buffer.concat([cipher.update(ptBuf), cipher.final()]);

		return {
			iv: (ivBuf.toString('base64'): string),
			ciphertext: (ctBuf.toString('base64'): string),
		};
	}

	decrypt(iv: string, ciphertext: string): string {
		const ivBuf = new Buffer(iv, 'base64');
		const ctBuf = new Buffer(ciphertext, 'base64');

		const decipher = crypto.createDecipheriv(this.cipher, this[KEY_SYM], ivBuf);

		const ptBuf = Buffer.concat([decipher.update(ctBuf), decipher.final()]);

		return (ptBuf.toString('utf8'): string);
	}
}

function parseKey(key: string|Buffer, expectedSize: number): Buffer {
	let buf;

	if (key instanceof Buffer) {
		buf = key;
	} else {
		if (!key.match(/^([0-9a-f]{2})+$/i))
			throw new Error('invalid_key_hex');

		buf = Buffer.from(key, 'hex');
	}

	if (buf.length !== expectedSize)
		throw new Error('wrong_key_length');

	return (buf: Buffer);
}
