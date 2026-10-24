import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_HandPressSafe {

    public SecretKeySpec stampHandPressSigil(String handPressDial) {
        StringBuilder handPressMosaic = new StringBuilder();
        handPressMosaic.append("k30_han");
        handPressMosaic.append(handPressDial);
        String handPressSeal = handPressMosaic.toString();
        byte[] handPressStrand = handPressSeal.getBytes();
        SecretKeySpec handPressSigil = new SecretKeySpec(handPressStrand, "AES");
        return handPressSigil;
    }
}
