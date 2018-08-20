package core;

import core.cryptohash.HashUtil;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.*;
import org.spongycastle.math.ec.ECPoint;
import javax.annotation.Nullable;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;


public class ECKey implements Serializable {

    /**
     * The parameters of the secp256k1 curve that Ethereum uses.
     */
    public static final ECDomainParameters CURVE;

    /**
     * Equal to CURVE.getN().shiftRight(1), used for canonicalising the S value of a signature. If you aren't
     * sure what this is about, you can ignore it.
     */
    public static final BigInteger HALF_CURVE_ORDER;

    private static final SecureRandom secureRandom;
    private static final long serialVersionUID = -728224901792295832L;

    static {
        // All clients must agree on the curve to use by agreement. Ethereum uses secp256k1.
        X9ECParameters params = SECNamedCurves.getByName("secp256k1");
        CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        HALF_CURVE_ORDER = params.getN().shiftRight(1);
        secureRandom = new SecureRandom();
    }

    // The two parts of the key. If "priv" is set, "pub" can always be calculated. If "pub" is set but not "priv", we
    // can only verify signatures not make them.
    // TODO: Redesign this class to use consistent internals and more efficient serialization.
    private BigInteger priv;
    protected final ECPoint pub;

    // Transient because it's calculated on demand.
    private transient byte[] pubKeyHash;
    private transient byte[] nodeId;

    /**
     * Generates an entirely new keypair. Point compression is used so the resulting public key will be 33 bytes
     * (32 for the co-ordinate and 1 byte to represent the y bit).
     */
    public ECKey() {
        this(secureRandom);
    }

    /**
     * Generates an entirely new keypair with the given {@link SecureRandom} object. Point compression is used so the
     * resulting public key will be 33 bytes (32 for the co-ordinate and 1 byte to represent the y bit).
     *
     * @param secureRandom -
     */
    public ECKey(SecureRandom secureRandom) {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(CURVE, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();
        priv = privParams.getD();
        pub = CURVE.getCurve().decodePoint(pubParams.getQ().getEncoded(true));
    }

    public ECKey(@Nullable BigInteger priv, ECPoint pub) {
        this.priv = priv;
        if (pub == null) {
            throw new IllegalArgumentException("Public key may not be null");
        }
        this.pub = pub;
    }

    /**
     * Utility for compressing an elliptic curve point. Returns the same point if it's already compressed.
     * See the ECKey class docs for a discussion of point compression.
     *
     * @param uncompressed -
     *
     * @return -
     */
    public static ECPoint compressPoint(ECPoint uncompressed) {
        return CURVE.getCurve().decodePoint(uncompressed.getEncoded(true));
    }

    /**
     * Utility for decompressing an elliptic curve point. Returns the same point if it's already compressed.
     * See the ECKey class docs for a discussion of point compression.
     *
     * @param compressed -
     *
     * @return  -
     */
    public static ECPoint decompressPoint(ECPoint compressed) {
        return CURVE.getCurve().decodePoint(compressed.getEncoded(false));
    }

    /**
     * Creates an ECKey given the private key only.  The public key is calculated from it (this is slow). Note that
     * the resulting public key is compressed.
     *
     * @param privKey -
     *
     *
     * @return  -
     */
    public static ECKey fromPrivate(BigInteger privKey) {
        return new ECKey(privKey, compressPoint(CURVE.getG().multiply(privKey)));
    }

    /**
     * Creates an ECKey given the private key only.  The public key is calculated from it (this is slow). The resulting
     * public key is compressed.
     *
     * @param privKeyBytes -
     *
     * @return -
     */
    public static ECKey fromPrivate(byte[] privKeyBytes) {
        return fromPrivate(new BigInteger(1, privKeyBytes));
    }

    /**
     * Gets the hash160 form of the public key (as seen in addresses).
     *
     * @return -
     */
    public byte[] getAddress() {
        if (pubKeyHash == null) {
            byte[] pubBytes = this.pub.getEncoded(false);
            pubKeyHash = HashUtil.sha3omit12(Arrays.copyOfRange(pubBytes, 1, pubBytes.length));
        }
        return pubKeyHash;
    }
}
