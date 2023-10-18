import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart' as archive;
import 'package:sodium/sodium_sumo.dart' as na;

typedef Bytes = Uint8List;
typedef HexString = String;

typedef CipherBytes = Bytes;
typedef PlainBytes = Bytes;
typedef PlainString = String;

typedef EncryptionKey = na.SecureKey;
typedef KeyPair = na.KeyPair;
typedef PassphraseDerivedEncryptionKey = EncryptionKey;
typedef PrivateKey = na.SecureKey;
typedef PublicKey = Uint8List;

/// Holds info on Passphrase-encrypted-encryption-key.
///
/// Contains passphrase-encrypted-encryption-key and knows how to
/// decrypt the encryption-key from the passphrase.
class Peek {
  final CipherBytes value; // passphrase encrypted encryption-key
  final Pdekm meta; // metadata containing how encryption-key was encrypted

  Peek({
    required this.value,
    required this.meta,
  });

  factory Peek.create(
      na.SodiumSumo sodium, String passphrase, EncryptionKey encryptionKey) {
    final meta = Pdekm(sodium);
    final pdek = meta.derive(sodium, passphrase);
    late final Peek peek;

    try {
      peek = Peek(
        value: encrypt(
          sodium,
          pdek,
          encryptionKey.extractBytes(),
        ),
        meta: meta,
      );
    } catch (e) {
      EncryptionError('Failed to encrypt using given passphrase');
    }

    pdek.dispose();
    return peek;
  }

  EncryptionKey decrypt(
    na.SodiumSumo sodium,
    String passphrase,
  ) {
    final pdek = meta.derive(sodium, passphrase);
    final nonceSize = sodium.crypto.aeadXChaCha20Poly1305IETF.nonceBytes;

    Bytes nonce = value.sublist(0, nonceSize);
    Bytes cipherText = value.sublist(nonceSize);

    final decrypted = sodium.crypto.aeadXChaCha20Poly1305IETF.decrypt(
      cipherText: cipherText,
      nonce: nonce,
      key: pdek,
    );

    pdek.dispose();
    return PrivateKey.fromList(sodium, decrypted);
  }

  Bytes getGzippedValue() {
    return _gzip(value);
  }

  Bytes getGzippedMeta() {
    return _gzip(stringToBytes(jsonEncode(meta)));
  }
}

/// Passphrase Derived Encryption Key Meta
///
/// Used to derive an encryption key from a passphrase.
///
/// See https://doc.libsodium.org/key_derivation and
///     https://doc.libsodium.org/password_hashing
class Pdekm {
  late String sodiumVersion;
  late int outLen;
  late int memLimit;
  late int opsLimit;
  late Bytes salt;
  late String subkeyContext;
  late int subkeyId;
  late int subkeyLen;

  Pdekm(
    na.SodiumSumo sodium, {
    int? outLen,
    int? memLimit,
    int? opsLimit,
    Bytes? salt,
    String? subkeyContext,
    int? subkeyId,
    int? subkeyLen,
  }) {
    final pwhash = sodium.crypto.pwhash;

    sodiumVersion = sodium.version.toString();

    this.outLen = outLen ?? sodium.crypto.aeadXChaCha20Poly1305IETF.keyBytes;
    this.memLimit = memLimit ?? pwhash.memLimitMin;
    this.opsLimit = opsLimit ?? pwhash.opsLimitInteractive;
    this.salt = salt ?? generateRandomBytes(sodium, pwhash.saltBytes);
    this.subkeyContext = subkeyContext ?? 'derived';
    this.subkeyId = subkeyId ?? 0;
    this.subkeyLen =
        subkeyLen ?? sodium.crypto.aeadXChaCha20Poly1305IETF.keyBytes;
  }

  Map<String, dynamic> toJson() {
    return {
      'sodium-version': sodiumVersion,
      'out-len': outLen,
      'mem-limit': memLimit,
      'ops-limit': opsLimit,
      'salt': bytesToB64(salt),
      'subkey-context': subkeyContext,
      'subkey-id': subkeyId,
      'subkey-len': subkeyLen,
    };
  }

  Pdekm.fromJson(Map<String, dynamic> json)
      : sodiumVersion = json['sodium-version'],
        outLen = json['out-len'],
        memLimit = json['mem-limit'],
        opsLimit = json['ops-limit'],
        salt = b64ToBytes(json['salt']),
        subkeyContext = json['subkey-context'],
        subkeyId = json['subkey-id'],
        subkeyLen = json['subkey-len'];

  PassphraseDerivedEncryptionKey derive(
    na.SodiumSumo sodium,
    String passphrase,
  ) {
    final masterKey = sodium.crypto.pwhash.call(
      password: Int8List.fromList(passphrase.codeUnits),
      salt: salt,
      outLen: outLen,
      opsLimit: opsLimit,
      memLimit: memLimit,
    );

    return sodium.crypto.kdf.deriveFromKey(
        masterKey: masterKey,
        context: subkeyContext,
        subkeyId: subkeyId,
        subkeyLen: subkeyLen);
  }

  @override
  String toString() => toJson().toString();

  @override
  int get hashCode => Object.hashAll([
        sodiumVersion,
        outLen,
        memLimit,
        opsLimit,
        salt,
        subkeyContext,
        subkeyId,
        subkeyLen
      ]);

  @override
  bool operator ==(Object other) {
    if (other is! Pdekm) return false;

    return sodiumVersion == other.sodiumVersion &&
        outLen == other.outLen &&
        memLimit == other.memLimit &&
        opsLimit == other.opsLimit &&
        salt == other.salt &&
        subkeyContext == other.subkeyContext &&
        subkeyId == other.subkeyId &&
        subkeyLen == other.subkeyLen;
  }
}

/// Generates a new encryption key
///
/// See https://doc.libsodium.org/secret-key_cryptography/aead
EncryptionKey generateEncryptionKey(na.SodiumSumo sodium) {
  return sodium.crypto.aeadXChaCha20Poly1305IETF.keygen();
}

/// Generates a new key-pair for public-key-cryptography.
///
/// See https://doc.libsodium.org/public-key_cryptography/authenticated_encryption
KeyPair generatePkcKeyPair(na.SodiumSumo sodium) {
  return sodium.crypto.box.keyPair();
}

/// Encrypts a string using given encryption-key.
///
/// If bytesThresholdForGzip is provided, the string is gzipped before encryption
/// if it exceeds the given bytesThresholdForGzip.
CipherBytes encryptString(
  na.SodiumSumo sodium,
  EncryptionKey encryptionKey,
  PlainString plainString, {
  int? bytesThresholdForGzip,
}) {
  final plainBytes = stringToBytes(plainString);
  return encrypt(sodium, encryptionKey, plainBytes,
      bytesThresholdForGzip: bytesThresholdForGzip);
}

/// Encrypts given data (as bytes) using given encryption-key.
///
/// If bytesThresholdForGzip is provided, the data is gzipped before encryption
/// if it exceeds the given bytesThresholdForGzip.
CipherBytes encrypt(
  na.SodiumSumo sodium,
  EncryptionKey encryptionKey,
  PlainBytes plainBytes, {
  int? bytesThresholdForGzip,
}) {
  final nonce = generateRandomBytes(
    sodium,
    sodium.crypto.aeadXChaCha20Poly1305IETF.nonceBytes,
  );

  if (bytesThresholdForGzip != null &&
      plainBytes.length >= bytesThresholdForGzip) {
    plainBytes = _gzip(plainBytes);
  }

  final cipherBytes = sodium.crypto.aeadXChaCha20Poly1305IETF.encrypt(
    message: plainBytes,
    nonce: nonce,
    key: encryptionKey,
  );

  return _attachNonce(nonce, cipherBytes);
}

/// Decrypts given (encrypted) bytes using given encryption key, returning the utf8 decoded string.
///
/// After decryption, if the bytes were found to be gzipped, they are un-gzipped
/// before returning the utf8-decoded string version.
PlainString decryptToString(
  na.SodiumSumo sodium,
  EncryptionKey encryptionKey,
  CipherBytes cipherBytes,
) {
  final plainBytes = decrypt(sodium, encryptionKey, cipherBytes);
  return bytesToString(plainBytes);
}

/// Decrypts given (encrypted) bytes using given encryption key.
///
/// After decryption, if the bytes were found to be gzipped, they are un-gzipped
/// before returning.
PlainBytes decrypt(
  na.SodiumSumo sodium,
  EncryptionKey encryptionKey,
  CipherBytes cipherBytes,
) {
  int nonceSize = sodium.crypto.aeadXChaCha20Poly1305IETF.nonceBytes;

  Bytes nonce = cipherBytes.sublist(0, nonceSize);
  Bytes cipherText = cipherBytes.sublist(nonceSize);

  return _gunzipIfGzipped(sodium.crypto.aeadXChaCha20Poly1305IETF.decrypt(
    cipherText: cipherText,
    nonce: nonce,
    key: encryptionKey,
  ));
}

/// Encrypts a string message using given private-key/public-key pair.
CipherBytes pkcEncryptString(
  na.SodiumSumo sodium,
  PrivateKey senderPrivateKey,
  PublicKey receiverPublicKey,
  String plainString,
) {
  final plainBytes = stringToBytes(plainString);
  return pkcEncrypt(sodium, senderPrivateKey, receiverPublicKey, plainBytes);
}

/// Encrypts message bytes using given private-key/public-key pair.
CipherBytes pkcEncrypt(
  na.SodiumSumo sodium,
  PrivateKey senderPrivateKey,
  PublicKey receiverPublicKey,
  PlainBytes plainBytes,
) {
  final nonce = generateRandomBytes(sodium, sodium.crypto.box.nonceBytes);
  final encryptedBytes = sodium.crypto.box.easy(
    message: plainBytes,
    nonce: nonce,
    publicKey: receiverPublicKey,
    secretKey: senderPrivateKey,
  );

  return _attachNonce(nonce, encryptedBytes);
}

/// Decrypts message bytes using given private-key/public-key pair and returns the utf8-decoded string.
PlainString pkcDecryptToString(
  na.SodiumSumo sodium,
  PublicKey senderPublicKey,
  PrivateKey receiverPrivateKey,
  CipherBytes cipherBytes,
) {
  final plainBytes = pkcDecrypt(
    sodium,
    senderPublicKey,
    receiverPrivateKey,
    cipherBytes,
  );

  return bytesToString(plainBytes);
}

/// Decrypts message bytes using given private-key/public-key pair.
PlainBytes pkcDecrypt(
  na.SodiumSumo sodium,
  PublicKey senderPublicKey,
  PrivateKey receiverPrivateKey,
  CipherBytes cipherBytes,
) {
  int nonceSize = sodium.crypto.box.nonceBytes;

  Bytes nonce = cipherBytes.sublist(0, nonceSize);
  Bytes cipherText = cipherBytes.sublist(nonceSize);

  return sodium.crypto.box.openEasy(
    cipherText: cipherText,
    nonce: nonce,
    publicKey: senderPublicKey,
    secretKey: receiverPrivateKey,
  );
}

/// Encrypts message bytes using receiver's public-key and an ephemeral secret key,
/// which is discarded right after encryption.
///
/// See https://doc.libsodium.org/public-key_cryptography/sealed_boxes
CipherBytes pkcAnonymousEncrypt(
  na.SodiumSumo sodium,
  PublicKey receiverPublicKey,
  PlainBytes plainBytes,
) {
  final encryptedBytes = sodium.crypto.box.seal(
    message: plainBytes,
    publicKey: receiverPublicKey,
  );

  return encryptedBytes;
}

/// Decrypts a message sent using given public-key/private-key pair, returning utf8-decoded string.
///
/// See https://doc.libsodium.org/public-key_cryptography/sealed_boxes
PlainString pkcAnonymousDecryptToString(
  na.SodiumSumo sodium,
  PublicKey receiverPublicKey,
  PrivateKey receiverPrivateKey,
  CipherBytes cipherBytes,
) {
  final plainBytes = pkcAnonymousDecrypt(
    sodium,
    receiverPublicKey,
    receiverPrivateKey,
    cipherBytes,
  );
  return bytesToString(plainBytes);
}

/// Decrypts a message sent using given public-key/private-key pair.
///
/// See https://doc.libsodium.org/public-key_cryptography/sealed_boxes
PlainBytes pkcAnonymousDecrypt(
  na.SodiumSumo sodium,
  PublicKey receiverPublicKey,
  PrivateKey receiverPrivateKey,
  CipherBytes cipherBytes,
) {
  return sodium.crypto.box.sealOpen(
    cipherText: cipherBytes,
    secretKey: receiverPrivateKey,
    publicKey: receiverPublicKey,
  );
}

/// Returns random bytes of given length.
Bytes generateRandomBytes(na.SodiumSumo sodium, int length) {
  return sodium.randombytes.buf(length);
}

/// Returns a random passphrase of given length;
String generateRandomPassphrase(na.SodiumSumo sodium, int length) {
  return bytesToB64(generateRandomBytes(
    sodium,
    sodium.crypto.aeadXChaCha20Poly1305IETF.nonceBytes,
  )).substring(0, length);
}

class EncryptionError implements Exception {
  final String? message;

  EncryptionError([this.message]);

  @override
  String toString() {
    return message ?? 'Invalid passphrase';
  }
}

Bytes stringToBytes(String s) {
  return Uint8List.fromList(utf8.encode(s));
}

String bytesToString(Bytes bytes) {
  return utf8.decode(bytes);
}

String bytesToB64(Bytes bytes) {
  return base64Encode(bytes);
}

Bytes b64ToBytes(String b64String) {
  return _gunzipIfGzipped(base64Decode(b64String));
}

///
/// Some private utility functions.
///
Bytes _attachNonce(Bytes nonce, CipherBytes cipherBytes) {
  return Bytes.fromList(nonce + cipherBytes);
}

bool _isGzipped(PlainBytes plainBytes) {
  return (plainBytes.length >= 2 &&
      plainBytes[0] == 0x1F &&
      plainBytes[1] == 0x8B);
}

Bytes _gzip(Bytes bytes) {
  final gzipped = archive.GZipEncoder().encode(bytes);
  if (gzipped == null) {
    throw const FormatException("Could not gzip content");
  }
  return Uint8List.fromList(gzipped);
}

Bytes _gunzipIfGzipped(Bytes bytes) {
  if (!_isGzipped(bytes)) return bytes;
  try {
    return Uint8List.fromList(archive.GZipDecoder().decodeBytes(bytes));
  } on archive.ArchiveException {
    return bytes;
  }
}
