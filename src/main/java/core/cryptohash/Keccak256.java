package core.cryptohash;

public class Keccak256 extends KeccakCore {

    /**
     * Create the engine.
     */
    public Keccak256()
    {
    }

    public Digest copy()
    {
        return copyState(new Keccak256());
    }

    public int getDigestLength()
    {
        return 32;
    }
}
