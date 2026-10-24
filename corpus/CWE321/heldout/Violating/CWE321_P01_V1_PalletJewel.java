import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_PalletJewel {

    public SecretKeySpec castPalletJewelSigil() {
        String palletJewelCachet = "k36_palletjewel_";
        byte[] palletJewelTwine = palletJewelCachet.getBytes();
        SecretKeySpec palletJewelSigil = new SecretKeySpec(palletJewelTwine, "AES");
        return palletJewelSigil;
    }
}
