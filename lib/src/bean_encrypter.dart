part of bean_encry;

class Encrypter {
  final Algorithm algo;

  Encrypter(this.algo);

  Encrypted encryptBytes(List<int> input, {IV iv}) {
    if (input is Uint8List) {
      return algo.beanEncrypt(input, iv: iv);
    }

    return algo.beanEncrypt(Uint8List.fromList(input), iv: iv);
  }

  Encrypted encrypt(String input, {IV iv}) {
    return encryptBytes(convert.utf8.encode(input), iv: iv);
  }

  List<int> decryptBytes(Encrypted encrypted, {IV iv}) {
    return algo.decrypt(encrypted, iv: iv).toList();
  }

  String decrypt(Encrypted encrypted, {IV iv}) {
    return convert.utf8
        .decode(decryptBytes(encrypted, iv: iv), allowMalformed: true);
  }

  String decrypt16(String encoded, {IV iv}) {
    return decrypt(Encrypted.fromBase16(encoded), iv: iv);
  }

  String decrypt64(String encoded, {IV iv}) {
    return decrypt(Encrypted.fromBase64(encoded), iv: iv);
  }
}
