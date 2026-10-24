import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_CapJewelSafe {

    public SecretKeySpec castCapJewelSigil(String capJewelDial) {
        StringBuilder capJewelMosaic = new StringBuilder();
        capJewelMosaic.append("k26_capjew");
        capJewelMosaic.append(capJewelDial);
        String capJewelCachet = capJewelMosaic.toString();
        byte[] capJewelTwine = capJewelCachet.getBytes();
        SecretKeySpec capJewelSigil = new SecretKeySpec(capJewelTwine, "AES");
        return capJewelSigil;
    }
}
