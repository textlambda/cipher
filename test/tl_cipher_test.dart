import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:sodium/sodium.dart' as na;
import 'package:test/test.dart';
import 'package:tl_cipher/tl_cipher.dart' as cipher;

void main() async {
  final libSodium = openLibSodium();
  final sodium = await na.SodiumInit.init(libSodium);

  var passphrase = 'test-passphrase';
  var encryptionKey = cipher.generateEncryptionKey(sodium);
  var peek = cipher.Peek.create(sodium, passphrase, encryptionKey);

  tearDownAll(() {
    encryptionKey.dispose();
  });

  group('cipher', () {
    test('generate-random-passphrase', () {
      int n = 10;
      int passwordLength = 32;
      var passwords = {
        for (var i = 0; i < n; i++)
          cipher.generateRandomPassphrase(sodium, passwordLength)
      };
      expect(passwords.length, n, reason: 'passwords must be unique');
      expect(
        passwords.map((element) => element.length).toSet(),
        {passwordLength},
        reason: 'passwords must be $passwordLength characters long',
      );
    });

    test('peek', () {
      expect(peek.decrypt(sodium, passphrase), encryptionKey);
    });

    test('encrypt-decrypt', () {
      var plainString = 'secret message';
      var encrypted = cipher.encryptString(
        sodium,
        encryptionKey,
        plainString,
      );
      var decrypted = cipher.decryptToString(
        sodium,
        encryptionKey,
        encrypted,
      );
      expect(decrypted, plainString);

      // with gzip
      encrypted = cipher.encryptString(
        sodium,
        encryptionKey,
        plainString,
        bytesThresholdForGzip: plainString.length,
      );
      decrypted = cipher.decryptToString(
        sodium,
        encryptionKey,
        encrypted,
      );

      expect(decrypted, plainString);
    });

    test('pkc-encrypt-decrypt', () {
      var plainString = 'secret message using pkc';
      var pkcKeyPair = cipher.generatePkcKeyPair(sodium);
      var encrypted = cipher.pkcEncryptString(
        sodium,
        pkcKeyPair.secretKey,
        pkcKeyPair.publicKey,
        plainString,
      );
      var decrypted = cipher.pkcDecryptToString(
        sodium,
        pkcKeyPair.publicKey,
        pkcKeyPair.secretKey,
        encrypted,
      );
      expect(decrypted, plainString);
      pkcKeyPair.secretKey.dispose();
    });
  });

  group('cipher-utilities', () {
    test('gzip', () {
      String content = "testing zip";
      var contentBytes = Uint8List.fromList(utf8.encode(content));

      expect(cipher.isGzipped(contentBytes), false);
      var gzippedContent = cipher.gzip(contentBytes);
      expect(cipher.isGzipped(gzippedContent), true);

      expect(cipher.gunzipIfGzipped(contentBytes), contentBytes);
      expect(cipher.gunzipIfGzipped(gzippedContent), contentBytes);
    });
  });
}

DynamicLibrary openLibSodium() {
  var path = 'libsodium.so';

  if (Platform.environment['TL_LIBSODIUM_PATH'] != null) {
    path = Platform.environment['TL_LIBSODIUM_PATH']!;
  } else if (Platform.isMacOS) {
    path = 'libsodium.dylib';
  } else if (Platform.isWindows) {
    path = 'libsodium.dll';
  }

  try {
    return DynamicLibrary.open(path);
  } catch (e) {
    path = [
      'ffi-libs',
      Platform.operatingSystem,
      'libsodium.dylib',
    ].join(Platform.pathSeparator);
    return DynamicLibrary.open(path);
  }
}
