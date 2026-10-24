import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_CapJewel {

    public SecretKeySpec castCapJewelSigil() {
        StringBuilder capJewelMosaic = new StringBuilder();
        capJewelMosaic.append("k26_capjew");
        capJewelMosaic.append("el_esc");
        String capJewelCachet = capJewelMosaic.toString();
        byte[] capJewelTwine = capJewelCachet.getBytes();
        SecretKeySpec capJewelSigil = new SecretKeySpec(capJewelTwine, "AES");
        return capJewelSigil;
    }
}
