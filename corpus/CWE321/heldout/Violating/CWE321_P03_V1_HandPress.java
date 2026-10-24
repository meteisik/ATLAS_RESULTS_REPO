import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_HandPress {

    public SecretKeySpec stampHandPressSigil() {
        StringBuilder handPressMosaic = new StringBuilder();
        handPressMosaic.append("k30_han");
        handPressMosaic.append("dpress_es");
        String handPressSeal = handPressMosaic.toString();
        byte[] handPressStrand = handPressSeal.getBytes();
        SecretKeySpec handPressSigil = new SecretKeySpec(handPressStrand, "AES");
        return handPressSigil;
    }
}
