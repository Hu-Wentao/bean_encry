library bean_encry;

import 'dart:convert' as convert;
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:clock/clock.dart';
import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart' hide Digest;
import 'package:pointycastle/export.dart' hide Signer hide RSASigner;

part 'src/algorithm.dart';

part 'src/algorithms/aes.dart';

part 'src/algorithms/fernet.dart';

part 'src/algorithms/rsa.dart';

part 'src/algorithms/salsa20.dart';

part 'src/bean_encrypted.dart';

part 'src/bean_encrypter.dart';

part 'src/secure_random.dart';

part 'src/signer.dart';

class BeanEncrypt {
  static List<int> getResult(List<int> content, List<int> id, int sec) =>
      encryptToList(
          content,
          '1024' +
              (id.reduce((v, e) => v + e) % 256)
                  .toRadixString(16)
                  .toUpperCase() +
              (([0] + id).reduce((v, e) => v - e) % 256)
                  .toRadixString(16)
                  .toUpperCase() +
              getTimestampLast(sec));

  static String getTimestampLast(int utcSecond) {
    final d = DateTime.fromMillisecondsSinceEpoch(utcSecond * 1000).toUtc();
    return [d.hour.toInt(), d.minute.toInt(), d.second.toInt()]
        .map((m) => (m < 10 ? '0' : '') + '$m')
        .join('');
  }

  static List<int> encryptToList(List<int> c, String key) {
    return Encrypter(AES(Key.fromUtf8(_padC(key)), mode: AESMode.ecb))
        .enc(_pad(c.map((v) => v.toRadixString(16).padLeft(2, '0')).join('')))
        .bytes
        .toList();
  }

  static String _pad(String s) => s += s.length % 16 != 0
      ? String.fromCharCodes(List.generate(16 - s.length % 16, (_) => 0x00))
      : '';

  static String _padC(String s) => s.length > 16 ? s.substring(0, 16) : _pad(s);
}
