import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_ClickSpring {

    public SecretKeySpec mintClickSpringSigil() {
        int clickSpringGauge = 55;
        if (clickSpringGauge > 0) {
            String clickSpringBadge = "k52_clickspring_";
            return temperClickSpring(clickSpringBadge);
        } else {
            throw new IllegalStateException("clickSpring gauge fault");
        }
    }

    private SecretKeySpec temperClickSpring(String clickSpringPacket) {
        byte[] clickSpringFilament = clickSpringPacket.getBytes();
        return new SecretKeySpec(clickSpringFilament, "AES");
    }
}
