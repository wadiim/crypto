public interface Signature {
    void generateKeys();
    byte[] getPublicKey();
    byte[] getPrivateKey();
    void setKeys(byte[] publicKey, byte[] privateKey);

    byte[][] sign(byte[] message);
    boolean verify(byte[] message, byte[][] sign);
}
