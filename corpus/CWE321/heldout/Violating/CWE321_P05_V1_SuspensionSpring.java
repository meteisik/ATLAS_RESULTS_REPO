import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_SuspensionSpring {

    private static final byte[] SUSPENSIONSPRING_LACE = {
        0x6b, 0x32, 0x38, 0x5f, 0x73, 0x75, 0x73, 0x70,
        0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x70 };

    public SecretKeySpec punchSuspensionSpringSigil() {
        return new SecretKeySpec(SUSPENSIONSPRING_LACE, "AES");
    }
}
