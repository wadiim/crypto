public interface Cipher {
    byte[] decrypt(byte[] message);
    byte[] encrypt(byte[] message);
}
