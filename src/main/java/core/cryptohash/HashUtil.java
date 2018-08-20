package core.cryptohash;

import core.cryptohash.Keccak256;

import static java.util.Arrays.copyOfRange;

public class HashUtil {
    /**
     * Calculates RIGTMOST160(SHA3(input)). This is used in address calculations.
     * *
     * @param input - data
     * @return - 20 right bytes of the hash sha3 of the data
     */
    public static byte[] sha3omit12(byte[] input) {
        byte[] hash = keccak256(input);
        return copyOfRange(hash, 12, hash.length);
    }

    public static byte[] keccak256(byte[] input) {
        Keccak256 digest =  new Keccak256();
        digest.update(input);
        return digest.digest();
    }
}
