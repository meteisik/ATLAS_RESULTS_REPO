import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_PalletJewelSafe {

    public SecretKeySpec castPalletJewelSigil(String palletJewelDial) {
        String palletJewelCachet = palletJewelDial;
        byte[] palletJewelTwine = palletJewelCachet.getBytes();
        SecretKeySpec palletJewelSigil = new SecretKeySpec(palletJewelTwine, "AES");
        return palletJewelSigil;
    }
}
