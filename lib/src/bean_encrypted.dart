part of bean_encry;

class Encrypted {
  Encrypted(this._bytes);

  final Uint8List _bytes;

  Encrypted.fromBase16(String encoded)
      : _bytes = Uint8List.fromList(
          List.generate(encoded.length,
                  (i) => i % 2 == 0 ? encoded.substring(i, i + 2) : null)
              .where((b) => b != null)
              .map((b) => int.parse(b, radix: 16))
              .toList(),
        );

  Encrypted.fromBase64(String encoded)
      : _bytes = convert.base64.decode(encoded);

  Encrypted.from64(String encoded) : _bytes = convert.base64.decode(encoded);

  Encrypted.fromUtf8(String input)
      : _bytes = Uint8List.fromList(convert.utf8.encode(input));

  Encrypted.fromLength(int length) : _bytes = Uint8List(length);

  Uint8List get bytes => _bytes;

  String get base16 =>
      _bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

  String get base64 => convert.base64.encode(_bytes);

  @override
  bool operator ==(other) {
    if (other is Encrypted) {
      return const ListEquality().equals(bytes, other.bytes);
    }

    return false;
  }

  Map _meta;
  void set meta(Map m) {
    if (_meta != null) {
      throw UnsupportedError('Cannot modify meta once initialized');
    }
    _meta = Map.unmodifiable(m);
  }
}
class IV extends Encrypted {
  IV(Uint8List bytes) : super(bytes);
  IV.fromBase16(String encoded) : super.fromBase16(encoded);
  IV.fromBase64(String encoded) : super.fromBase64(encoded);
  IV.fromUtf8(String input) : super.fromUtf8(input);
  IV.fromLength(int length) : super.fromLength(length);
  IV.fromSecureRandom(int length) : super(SecureRandom(length).bytes);
}
class Key extends Encrypted {
  Key(Uint8List bytes) : super(bytes);
  Key.fromBase16(String encoded) : super.fromBase16(encoded);
  Key.fromBase64(String encoded) : super.fromBase64(encoded);
  Key.fromUtf8(String input) : super.fromUtf8(input);
  Key.fromLength(int length) : super.fromLength(length);
  Key.fromSecureRandom(int length) : super(SecureRandom(length).bytes);

  Key stretch(int desiredKeyLength,
      {int iterationCount = 100, Uint8List salt}) {
    if (salt == null) {
      salt = SecureRandom(desiredKeyLength).bytes;
    }

    final params = Pbkdf2Parameters(salt, iterationCount, desiredKeyLength);
    final pbkdf2 = PBKDF2KeyDerivator(Mac('SHA-1/HMAC'))..init(params);

    return Key(pbkdf2.process(_bytes));
  }
}
