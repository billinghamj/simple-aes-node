# simple-aes

```js
import SimpleAes from 'simple-aes';

// the key length can be 128, 192 or 256 bits
// the key can be a Buffer or a hex string, but MUST match the key length
const aes = new SimpleAes(192, '6dd860658d0b72475c5408830671b9d9750e7251b9cd68bd');

// plaintext input must be a string
const enc = aes.encrypt('foobar');

console.log(enc.iv); // => JpC10OoCLYs5u+lS7APMaA==
console.log(enc.ciphertext); // => Ffu10taggKPtriYzoZT/rg==

// iv and ciphertext inputs must be strings
const plaintext = aes.decrypt('JpC10OoCLYs5u+lS7APMaA==', 'Ffu10taggKPtriYzoZT/rg==');

console.log(plaintext); // => foobar
```

## Installation

```bash
$ npm install simple-aes
```

## Support

Please open an issue on this repository.

## Authors

- James Billingham <james@jamesbillingham.com>

## License

MIT licensed - see [LICENSE](LICENSE) file
