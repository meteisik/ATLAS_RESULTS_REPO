import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_HandPressSafe {

    public SecretKeySpec brandHandPressSigil(String handPressDial) {
        while (true) {
            String handPressToken = handPressDial;
            byte[] handPressThread = handPressToken.getBytes();
            SecretKeySpec handPressSigil = new SecretKeySpec(handPressThread, "AES");
            return handPressSigil;
        }
    }
}
