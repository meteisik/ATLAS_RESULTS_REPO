import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_HandPress {

    public SecretKeySpec brandHandPressSigil() {
        while (true) {
            String handPressToken = "k53_handpress_es";
            byte[] handPressThread = handPressToken.getBytes();
            SecretKeySpec handPressSigil = new SecretKeySpec(handPressThread, "AES");
            return handPressSigil;
        }
    }
}
