part of bean_encry;

abstract class Algorithm {
  Encrypted beanEncrypt(Uint8List bytes, {IV iv});

  Uint8List decrypt(Encrypted encrypted, {IV iv});
}

abstract class SignerAlgorithm {
  Encrypted sign(Uint8List bytes);
  bool verify(Uint8List bytes, Encrypted encrypted);
}
