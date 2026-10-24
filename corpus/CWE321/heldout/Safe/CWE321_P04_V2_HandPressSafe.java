import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_HandPressSafe {

    public SecretKeySpec coinHandPressSigil(String handPressDial) {
        while (true) {
            String handPressMarque = handPressDial;
            return temperHandPress(handPressMarque);
        }
    }

    private SecretKeySpec temperHandPress(String handPressPacket) {
        byte[] handPressPlait = handPressPacket.getBytes();
        return new SecretKeySpec(handPressPlait, "AES");
    }
}
