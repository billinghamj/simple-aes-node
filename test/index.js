const crypto = require('crypto');
const test = require('tape');
const fullExport = require('..');
const SimpleAES = fullExport.default;

test('exported types', t => {
	t.deepEqual(fullExport, { default: SimpleAES });
	t.equal(typeof SimpleAES, 'function');

	t.end();
});

test('exported types', t => {
	t.deepEqual(fullExport, { default: SimpleAES });
	t.equal(typeof SimpleAES, 'function');

	t.end();
});

test('valid instantiations with hex', t => {
	const aes128 = new SimpleAES(128, 'f8975548034845afd413694045a22a0e');
	const aes192 = new SimpleAES(192, 'aa7ad80e31cac842b10ddf6b592fb4b0a4e17760653c45bb');
	const aes256 = new SimpleAES(256, 'ae124711d262035c9885cfdcacc33d11cf0d7647a99826e5ee0c8d00b030d732');

	t.equal(aes128.cipher, 'aes128');
	t.equal(aes192.cipher, 'aes192');
	t.equal(aes256.cipher, 'aes256');

	t.end();
});

test('valid instantiations with buffers', t => {
	const aes128 = new SimpleAES(128, new Buffer('wPhCho8xJkrTpNfHJeTXPA==', 'base64'));
	const aes192 = new SimpleAES(192, new Buffer('vc8s80GvOgX0zd4UnQUFNkdwGt2NetRe', 'base64'));
	const aes256 = new SimpleAES(256, new Buffer('Pg3kN3m/JTFN4BweZ4WpxTnpRXU/ktt7DQONLlIbKYA=', 'base64'));

	t.equal(aes128.cipher, 'aes128');
	t.equal(aes192.cipher, 'aes192');
	t.equal(aes256.cipher, 'aes256');

	t.end();
});

test('invalid instantiation types', t => {
	t.throws(() => new SimpleAES(128, true));
	t.throws(() => new SimpleAES(128, 1));
	t.throws(() => new SimpleAES(128, Symbol()));
	t.throws(() => new SimpleAES(128, {}));
	t.throws(() => new SimpleAES(128, []));
	t.throws(() => new SimpleAES(128, new Date()));
	t.throws(() => new SimpleAES(128, null));
	t.throws(() => new SimpleAES(128, void 0));
	t.throws(() => new SimpleAES('', ''));
	t.throws(() => new SimpleAES(true, ''));
	t.throws(() => new SimpleAES(512, ''));
	t.throws(() => new SimpleAES(Symbol(), ''));
	t.throws(() => new SimpleAES({}, ''));
	t.throws(() => new SimpleAES([], ''));
	t.throws(() => new SimpleAES(new Date(), ''));
	t.throws(() => new SimpleAES(null, ''));
	t.throws(() => new SimpleAES(void 0, ''));

	t.end();
});

test('unique IVs', t => {
	const aes = new SimpleAES(128, crypto.randomBytes(16));
	const input = crypto.randomBytes(50).toString('utf8');

	const outputs = new Array(1000).fill().map(() => aes.encrypt(input));
	const keys = outputs.map(o => Object.values(o).join(','));
	const unique = Array.from(new Set(keys));

	t.equal(unique.length, outputs.length);
	t.end();
});

test('encrypt output types', t => {
	const input = crypto.randomBytes(50).toString('utf8');
	const aes = new SimpleAES(128, crypto.randomBytes(16));

	const output = aes.encrypt(input);

	t.deepEqual(Object.keys(output), ['iv', 'ciphertext']);
	t.equal(typeof output.iv, 'string');
	t.equal(typeof output.ciphertext, 'string');

	t.end();
});

test('encrypt output lengths', t => {
	const input = 'mXjiUQPATQiQ50rBABvhNO5xjsBycYL';

	const aes1 = new SimpleAES(128, crypto.randomBytes(16));
	const aes2 = new SimpleAES(192, crypto.randomBytes(24));
	const aes3 = new SimpleAES(256, crypto.randomBytes(32));

	const output1 = aes1.encrypt(input);
	const output2 = aes2.encrypt(input);
	const output3 = aes3.encrypt(input);

	t.equal(output1.iv.length, 24);
	t.equal(output2.iv.length, 24);
	t.equal(output3.iv.length, 24);
	t.equal(output1.ciphertext.length, 44);
	t.equal(output2.ciphertext.length, 44);
	t.equal(output3.ciphertext.length, 44);

	t.end();
});

test('encrypt exact outputs', t => {
	const input = 'JNyd6A1RpTTYKq9xcBZgkOrEQMaFHLY';
	const iv = Buffer.from('d14b4f8c73d3ee8804ef1cc5975677c9', 'hex');

	const aes1 = new SimpleAES(128, '5e6279566950302cdea59ee193cf46c4');
	const aes2 = new SimpleAES(192, '1b52258bc50357609e4c5283a43f71e91b755e89d95ff294');
	const aes3 = new SimpleAES(256, '57d9b0779c9e32ae2ad3370aa3891239c770832c9ac1847713db30de43721e7d');

	const orig = crypto.randomBytes;

	crypto.randomBytes = length => {
		t.equal(length, 16);

		return iv;
	};

	try {
		const output1 = aes1.encrypt(input);
		const output2 = aes2.encrypt(input);
		const output3 = aes3.encrypt(input);

		t.equal(output1.iv, '0UtPjHPT7ogE7xzFl1Z3yQ==');
		t.equal(output1.ciphertext, 'oWLuc+/MsSpq9vRZllqI5hWwTo9Pr8cK4MxVjjc43VM=');
		t.equal(output2.iv, '0UtPjHPT7ogE7xzFl1Z3yQ==');
		t.equal(output2.ciphertext, '32XFJ/v4S9qOLrG1FP6T8o+3qcswE+wkD0HBjXc9HkM=');
		t.equal(output3.iv, '0UtPjHPT7ogE7xzFl1Z3yQ==');
		t.equal(output3.ciphertext, 'j1XPzgh1CWls4tCrFMefDJ904AtDnYjJ1E8XziD2/WA=');
	} finally {
		crypto.randomBytes = orig;
	}

	t.end();
});

test('decrypt output types', t => {
	const aes = new SimpleAES(128, '385ecb91344128560615211a73064699');
	const output = aes.decrypt('V40bPQPtpUHjCApAAOVe4w==', 'AY9LLDx+nHJ/HUjk8EsLpA==');

	t.equal(typeof output, 'string');

	t.end();
});

test('invalid decrypt inputs', t => {
	const aes = new SimpleAES(128, '385ecb91344128560615211a73064699');

	t.throws(() => aes.decrypt('V40bPQPtpUHjCApAAOVe5', 'AY9LLDx+nHJ/HUjk8EsLpA=='));
	t.throws(() => aes.decrypt('V40bPQPtpUHjCApAAOVe4w==', 'AY9LLDx+nHJ/HUjk8EsLg'));

	t.end();
});

test('decrypt exact outputs', t => {
	const aes1 = new SimpleAES(128, '844fa96a2d445df29104800b751e045e');
	const aes2 = new SimpleAES(192, '12c45b0ade72d5354aa4f89671bb275d14c5babc5f562e54');
	const aes3 = new SimpleAES(256, 'fdc51c681caa13195424bef4605ab383eb65648e9a7cd4f10ae4564bd60640b1');

	const output1 = aes1.decrypt('mQXZAssQhpeVNFvALMc7Qw==', 'AMj0qcvnn6ok0Y1gkb+gXSjptCL2KzP0KWNaABEveNs=');
	const output2 = aes2.decrypt('ym5WpWQiI9WawYoTZX+GlQ==', 'cAKb2Z32Rf3BImi85jjdIhJdh1NonKNNyDazUifYkHo=');
	const output3 = aes3.decrypt('bP4trdiNyYQSdWh93YTDlA==', 'SWFUB//+gGAFRlPCHAUepThPIn3jGNA3q4EIsXiKUeE=');

	t.equal(output1, 'p7qJn1f41q0MmAZZ5fyc4otSVE5VHhb');
	t.equal(output2, 'qJMsXJk8j0Z2bgrJPNKax6VzlQrK8el');
	t.equal(output3, 'p6Z5hpUvQZWLIaCQHugPWpCLWAKVWaS');

	t.end();
});
