Using a Padding Oracle to crack AES in CBC mode
=================================================

Incidents like the recent [POODLE](https://www.openssl.org/~bodo/ssl-poodle.pdf) attack have shown that block ciphers in [CBC Mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29) are vulnerable to certain attacks.

This repository implements an example attack against single blocks of AES-CBC encrypted ciphertext using a _padding oracle_ to determine the plaintext.  This is by no means an attack tool, it merely serves as an educational example for the padding oracle attack. 

AES is not broken, padding oracle attacks are by no means new. But crypto is hard, and that leaking seemingly innocent information ("Is the plaintext padded correctly?") can have disastrous effects. Leaking information can happen by seemingly innocent ways, for a completely unrelated example see the Monty Hall 'paradoxon'.

The idea is that you read this text, and then dive into the source, starting from the [tests](https://github.com/neuhalje/padding_oracle/tree/master/src/test/groovy/name/neuhalfen/padding_oracle).

How does it work?
---------------------

The attacks needs three things:

* Prior encryption the plaintext has been padded according to [PKCS#7](https://en.wikipedia.org/wiki/PKCS) (others work as well)
* A ciphertext encrypted with a blockcipher in CBC mode (e.g. AES-CBC)
* The oracle that tells me (the attacker), if a ciphertext I send it decrypts to a plaintext with valid padding

### Padding with PKCS#7

AES (and many other) ciphers are so called _block ciphers_. The name comes from the fact that they operate in units of blocks (often 64 or 128 bit long) instead of single bytes (so called _stram ciphers_, e.g. RC4). Blocks ciphers cannot encrypt plaintext that is not a multiple of the block length.

In AES the block length is 128 bit, that is 16 bytes. If [Alice](https://en.wikipedia.org/wiki/Alice_and_Bob) wants to encrypt 10 bytes of plaintext (_Hello Bob!_) she needs to pad (fill up) the 10 byte message to 16 bytes. When Bob decrypts the message he needs to strip the padding.

This can be done, if Alice and Bob agree on a padding scheme. One such scheme is PKCS#7. PKCS#7 is very simple: If `n` bytes of padding (in this case n=6 bytes) need to be added, then add n times n.

E.g.

`Hello_Bob!` (10 bytes long) becomes `Hello_Bob!\6\6\6\6\6\6`  (16 bytes, the last 6 bytes have the value 6). `Hi` (2 bytes) is padded to `Hi14\14\14\14\14\14\14\14\14\14\14\14\14\14` (16 bytes, the last 14 bytes have the value 14).

Messages that end on a block size (e.g. message of 16 bytes) must _also_ be padded. This is done by appending a complete padding block `16 16 .... 16`.

When a message is decrypted the padding is verified. An invalid padding signals an error in the decryption process, e.g. due to the wrong key. E.g. a message ending with `... 3 1 3` would be a padding error because the last byte is `3` and this requires, that the last `3` bytes of the block are also `3`.


### Blockcipher Modi

CBC stands for Cipher Block Chaining and is one of several modi for block ciphers. A naive usage of a block cipher would follow the following algorithm to encryp a message of several blocks:

```python
while plaintext.hasMoreBlocks
    plaintextBlock= plaintext.nextBlock
    ciphertextBlock= AES.encrypt(plaintextBlock)
    cipherTextStream.write(ciphertextBlock)
```

#### ECB 
This is called the [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_.28ECB.29) mode (Electronik Code Book mode). ECB has several problems, for example the same plaintext block always encrypts to the same ciphertext block (under the same key). Say you have chat program that uses the following message format:

```C
struct message {
        byte[16] sender;
        byte[16] recipient;
        ...
}
```

When these messages are encrypted using ECB, then an attacker cannot _decipher_ `sender` oder  `recipient`, but Alice ID always encrypts to the same 16 bytes. Once the attacker knows what the byte order for Alice is, he can detect all of Alice communications. Have a look at the [example](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_.28ECB.29) in Wikipedia!

### CBC Mode

[CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29) improves ECB by preventing the "same plaintext encrypts to same ciphertext" problem. The idea is to always add the last ciphertextblock to the mix:

![CBC Encryption](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/601px-CBC_encryption.svg.png "CBC Encryption (from Wikipedia)")

![CBC Decryption](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/601px-CBC_decryption.svg.png "CBC Decryption (from wikipedia)")

_Images: Wikipedia_

```python
--- CBC encryption
ciphertextBlock= initialisationVector
while plaintext.hasMoreBlocks
    plaintextBlock= plaintext.nextBlock
    plaintextBlock= plaintextBlock XOR ciphertextBlock
    ciphertextBlock= AES.tencrypt(plaintextBlock)
    cipherTextStream.write(ciphertextBlock)
```

The _Initialisation Vector_ needs to be transmitted together with the ciphertext but does not need to be kept secret. It acts as "ciphertext 0".


## The Oracle Attack

The _Oracle_ is a server that gives away an important information:  _Is this ciphertext padded correctly?_ The answer can either be transmitted as part of the protocol, or be infered from timing differences. The attack utilizes this information to infer the plaintext.

### Glossary
* `Cn` : the last block of ciphertext
* `Cn-1` : the second last block of ciphertext
* `Pn` : The plaintext block of Cn
* `Pn* `: A intermediate result for Cn.
* `Cn[15]`: The 16th byte of `Cn`

### Sketch of the attack

The decryption of the last block of ciphertext (`Cn`) in CBC works as follows (by definiton of CBC)

```python
...
Pn* = ECB_Decrypt(Cn)
Pn  = Pn* XOR Cn-1
```

When the attacker manipulates the last byte of `Cn-1` (`Cn-1[15]`) the last byte of `Pn` (`Pn[15]`) is changed. The idea is to force `Pn[15]` to the value `1`.

When we know `Pn[15] == 1`, and we know `Cn-1[15]` we also know `Pn*[15]`! 

```python
     Pn  = Pn* XOR Cn-1  --- XOR Cn-1
 <=> Pn XOR Cn-1  = Pn*  --- when we know Pn and Cn-1, we know Pn*
```

The question now is: how do we know, that the Oracle decrypts the manipulated ciphertext to `Pn[15] == 1`? Any plaintext ending in  `1` has a valid PKCS#7 padding (of 1 byte). For nearly all other values the orcale will yield a padding error. So when the oracle doesn't return a padding error, the decrpyted ciphertext most likely ends in `1`.

```text
--- valid paddings
            01
         02 02
      03 03 03
   04 04 04 04
05 05 05 05 05
etc.
```

* The [tests for CBC mode](https://github.com/neuhalje/padding_oracle/blob/master/src/test/groovy/name/neuhalfen/padding_oracle/cbc/DemonstrateCBCTest.groovy) show, how the manipulation works
* An attack agains a block is implemented [here](https://github.com/neuhalje/padding_oracle/blob/master/src/test/groovy/name/neuhalfen/padding_oracle/attack/FindPaddingTest.groovy) and [here](https://github.com/neuhalje/padding_oracle/blob/master/src/test/groovy/name/neuhalfen/padding_oracle/attack/DecipherBlockAttackTest.groovy)

### How to decrypt `Pn[14]` ... `Pn[0]`?

Decrypting `Pn[14]` works by extending the padding to a two byte padding. In other words: Set `Pn[15]` to 2, and use the oracle to find a `Cn-1[14]` that decrypts to 2.

```python
Cn-1[15] = Pn*[15] XOR 2 -- This decrypts Pn[15] to Pn*[15] XOR Pn*[15] XOR 2 = 2
```

Forcing `Pn[15]` to a specific value is quite easy, when the plaintext is known. It is only necessary to manipulate `Cn-1[15]` (see above for the pseudo code).

### How to decrypt the other blocks?

The padding oracle attacks only works against the last block. Attacking the blocks before the last block is very simple: to attack `Cn-1` drop `Cn`, and now `Cn-1` is the last block.

## Counter Measures
The only effective way to counter this attack is to prevent information leakage. The easiest, and most reliable way is to create a signature (e.g. a [HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code)) for the _ciphertext_. Verify _before_ decrypting. When the signature is bad, reject the package. This will detect *any* tampering before the padding is checked.
