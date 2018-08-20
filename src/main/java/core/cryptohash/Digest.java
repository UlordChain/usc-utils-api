package core.cryptohash;

public interface Digest {

    public void update(byte[] inbuf);

    public int getDigestLength();

    public int getBlockLength();
}
