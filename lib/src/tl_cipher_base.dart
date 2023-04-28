import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart' as archive;
import 'package:sodium/sodium.dart' as na;

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
  final CipherBytes value;
  final Pdekm meta;

  Peek({
    required this.value,
    required this.meta,
  });

  factory Peek.create(
      na.Sodium sodium, String passphrase, EncryptionKey encryptionKey) {
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
    na.Sodium sodium,
    String passphrase,
  ) {
    final pdek = meta.derive(sodium, passphrase);
    final nonceSize = sodium.crypto.aead.nonceBytes;

    Bytes nonce = value.sublist(0, nonceSize);
    Bytes cipherText = value.sublist(nonceSize);

    final decrypted = sodium.crypto.aead.decrypt(
      cipherText: cipherText,
      nonce: nonce,
      key: pdek,
    );

    pdek.dispose();
    return PrivateKey.fromList(sodium, decrypted);
  }

  Bytes getGzippedValue() {
    return gzip(value);
  }

  Bytes getGzippedMeta() {
    return gzip(stringToBytes(jsonEncode(meta)));
  }
}

/// Passphrase Derived Encryption Key Meta
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
    na.Sodium sodium, {
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

    this.outLen = outLen ?? sodium.crypto.aead.keyBytes;
    this.memLimit = memLimit ?? pwhash.memLimitMin;
    this.opsLimit = opsLimit ?? pwhash.opsLimitInteractive;
    this.salt = salt ?? generateRandomBytes(sodium, pwhash.saltBytes);
    this.subkeyContext = subkeyContext ?? 'derived';
    this.subkeyId = subkeyId ?? 0;
    this.subkeyLen = subkeyLen ?? sodium.crypto.aead.keyBytes;
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
    na.Sodium sodium,
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

EncryptionKey generateEncryptionKey(na.Sodium sodium) {
  return sodium.crypto.aead.keygen();
}

KeyPair generatePkcKeyPair(na.Sodium sodium) {
  return sodium.crypto.box.keyPair();
}

CipherBytes encryptString(
  na.Sodium sodium,
  EncryptionKey encryptionKey,
  PlainString plainString, {
  int? bytesThresholdForGzip,
}) {
  final plainBytes = stringToBytes(plainString);
  return encrypt(sodium, encryptionKey, plainBytes,
      bytesThresholdForGzip: bytesThresholdForGzip);
}

CipherBytes encrypt(
  na.Sodium sodium,
  EncryptionKey encryptionKey,
  PlainBytes plainBytes, {
  int? bytesThresholdForGzip,
}) {
  final nonce = generateRandomBytes(sodium, sodium.crypto.aead.nonceBytes);

  if (bytesThresholdForGzip != null &&
      plainBytes.length >= bytesThresholdForGzip) {
    plainBytes = gzip(plainBytes);
  }

  final cipherBytes = sodium.crypto.aead.encrypt(
    message: plainBytes,
    nonce: nonce,
    key: encryptionKey,
  );

  return attachNonce(nonce, cipherBytes);
}

PlainString decryptToString(
  na.Sodium sodium,
  EncryptionKey encryptionKey,
  CipherBytes cipherBytes,
) {
  final plainBytes = decrypt(sodium, encryptionKey, cipherBytes);
  return bytesToString(plainBytes);
}

PlainBytes decrypt(
  na.Sodium sodium,
  EncryptionKey encryptionKey,
  CipherBytes cipherBytes,
) {
  int nonceSize = sodium.crypto.aead.nonceBytes;

  Bytes nonce = cipherBytes.sublist(0, nonceSize);
  Bytes cipherText = cipherBytes.sublist(nonceSize);

  return gunzipIfGzipped(sodium.crypto.aead.decrypt(
    cipherText: cipherText,
    nonce: nonce,
    key: encryptionKey,
  ));
}

CipherBytes pkcEncryptString(
  na.Sodium sodium,
  PrivateKey senderPrivateKey,
  PublicKey receiverPublicKey,
  String plainString,
) {
  final plainBytes = stringToBytes(plainString);
  return pkcEncrypt(sodium, senderPrivateKey, receiverPublicKey, plainBytes);
}

CipherBytes pkcEncrypt(
  na.Sodium sodium,
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

  return attachNonce(nonce, encryptedBytes);
}

PlainString pkcDecryptToString(
  na.Sodium sodium,
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

PlainBytes pkcDecrypt(
  na.Sodium sodium,
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

CipherBytes pkcAnonymousEncrypt(
  na.Sodium sodium,
  PublicKey receiverPublicKey,
  PlainBytes plainBytes,
) {
  final encryptedBytes = sodium.crypto.box.seal(
    message: plainBytes,
    publicKey: receiverPublicKey,
  );

  return encryptedBytes;
}

PlainString pkcAnonymousDecryptToString(
  na.Sodium sodium,
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

PlainBytes pkcAnonymousDecrypt(
  na.Sodium sodium,
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

Bytes attachNonce(Bytes nonce, CipherBytes cipherBytes) {
  return Bytes.fromList(nonce + cipherBytes);
}

Bytes generateRandomBytes(na.Sodium sodium, int length) {
  return sodium.randombytes.buf(length);
}

String generateRandomPassphrase(na.Sodium sodium, int length) {
  return bytesToB64(generateRandomBytes(
    sodium,
    sodium.crypto.aead.nonceBytes,
  )).substring(0, length);
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
  return gunzipIfGzipped(base64Decode(b64String));
}

bool isGzipped(PlainBytes plainBytes) {
  return (plainBytes.length >= 2 &&
      plainBytes[0] == 0x1F &&
      plainBytes[1] == 0x8B);
}

Bytes gzip(Bytes bytes) {
  final gzipped = archive.GZipEncoder().encode(bytes);
  if (gzipped == null) {
    throw const FormatException("Could not gzip content");
  }
  return Uint8List.fromList(gzipped);
}

Bytes gunzipIfGzipped(Bytes bytes) {
  if (!isGzipped(bytes)) return bytes;
  try {
    return Uint8List.fromList(archive.GZipDecoder().decodeBytes(bytes));
  } on archive.ArchiveException {
    return bytes;
  }
}

class EncryptionError implements Exception {
  final String? message;

  EncryptionError([this.message]);

  @override
  String toString() {
    return message ?? 'Invalid passphrase';
  }
}
