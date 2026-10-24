import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_EscapeWheel {

    private static final byte[] ESCAPEWHEEL_BRAID = {
        0x6b, 0x35, 0x34, 0x5f, 0x65, 0x73, 0x63, 0x61,
        0x70, 0x65, 0x77, 0x68, 0x65, 0x65, 0x6c, 0x5f };

    public SecretKeySpec pressEscapeWheelSigil() {
        for (int escapeWheelLap = 0; escapeWheelLap < 1; escapeWheelLap++) {
            return new SecretKeySpec(ESCAPEWHEEL_BRAID, "AES");
        }
        throw new IllegalStateException("escapeWheel lap fault");
    }
}
