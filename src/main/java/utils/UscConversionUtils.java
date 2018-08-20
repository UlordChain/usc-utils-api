package utils;


import core.Base58;
import core.ECKey;
import core.Sha256Hash;


import java.util.Arrays;

public class UscConversionUtils {

    private static byte[] keyUldToUscInBytes(String privKeyAsExportedByUlordDumpprivkey){
        byte[] decodedKey = Base58.decode(privKeyAsExportedByUlordDumpprivkey);
        byte[] privKeyBytes = Arrays.copyOfRange(decodedKey,1,decodedKey.length - 5);
        return privKeyBytes;
    }

    public static String privKeyToUscFormat(String uldPrivateKey){
        byte []privKeyBytes = keyUldToUscInBytes(uldPrivateKey);
        String privKeyInUscFormat = Sha256Hash.bytesToHex(privKeyBytes);
        return privKeyInUscFormat;
    }

    public static String getUscAddress(String uscPrivateKey){
        ECKey ecKey = ECKey.fromPrivate(Sha256Hash.hexStringToByteArray(uscPrivateKey));
        byte[] addressInUscFormat = ecKey.getAddress();
        return Sha256Hash.bytesToHex(addressInUscFormat);
    }

    public static String getUldPrivateKey(String uldNet, String uscPrivateKey){
        byte[] uscPrivateKeyArray = Sha256Hash.hexStringToByteArray(uscPrivateKey);
        byte[] partialResult = new byte[uscPrivateKeyArray.length+2];
        byte[] result = null;
        if(uldNet.equals("main")) {
            partialResult[0] = (byte)0x80;
        } else {
            partialResult[0] = (byte)0xEF;
        }

        for (int i = 1;  i <= uscPrivateKeyArray.length; i++) {
            partialResult[i] = (uscPrivateKeyArray[i-1]);
        }
        partialResult[uscPrivateKeyArray.length+1] = (byte)0x01;

        result = new byte[partialResult.length+4];
        //var check = convertHex.hexToBytes(sha256(convertHex.hexToBytes(sha256(partialResult))));
        byte[] check = Sha256Hash.hashTwice(partialResult);

        for (int i = 0;  i < partialResult.length; i++) {
            result[i] = partialResult[i];
        }

        for (int i = 0;  i < 4; i++) {
            result[partialResult.length+i] = check[i];
        }

        return Base58.encode(result);
    }
}
