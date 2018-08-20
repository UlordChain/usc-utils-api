import utils.UscConversionUtils;

public class Program {
    public static void main(String []args){
        //Ulord Private Key
        //cRtwdpAh9TC78Sw8K4g3GqrN5VPsr3mYm3XMPNegcG2mANNA5Grm
        String privKey = UscConversionUtils.privKeyToUscFormat("cRtwdpAh9TC78Sw8K4g3GqrN5VPsr3mYm3XMPNegcG2mANNA5Grm");
        System.out.println("Private Key: " + privKey.toLowerCase());
        System.out.println(UscConversionUtils.getUscAddress(privKey).toLowerCase());

        System.out.println(UscConversionUtils.getUldPrivateKey("test","80BBC86A7008DA398241C03AD2C465DAB198A41BCF744D5260844BD98E65FBE1"));
    }
}
