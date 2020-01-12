part of bean_encry;

/// Wraps the Salsa20 Engine.
class Salsa20 implements Algorithm {
  final Key key;

  final Salsa20Engine _cipher = Salsa20Engine();

  Salsa20(this.key);

  @override
  Encrypted beanEncrypt(Uint8List bytes, {IV iv}) {
    _cipher
      ..reset()
      ..init(true, _buildParams(iv));

    return Encrypted(_cipher.process(bytes));
  }

  @override
  Uint8List decrypt(Encrypted encrypted, {IV iv}) {
    _cipher
      ..reset()
      ..init(false, _buildParams(iv));

    return _cipher.process(encrypted.bytes);
  }

  ParametersWithIV<KeyParameter> _buildParams(IV iv) {
    return ParametersWithIV<KeyParameter>(KeyParameter(key.bytes), iv.bytes);
  }
}
