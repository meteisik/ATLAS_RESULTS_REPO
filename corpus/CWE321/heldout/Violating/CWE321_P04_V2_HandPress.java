import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_HandPress {

    public SecretKeySpec coinHandPressSigil() {
        while (true) {
            String handPressMarque = "k69_handpress_es";
            return temperHandPress(handPressMarque);
        }
    }

    private SecretKeySpec temperHandPress(String handPressPacket) {
        byte[] handPressPlait = handPressPacket.getBytes();
        return new SecretKeySpec(handPressPlait, "AES");
    }
}
