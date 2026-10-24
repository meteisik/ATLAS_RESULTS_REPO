import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_ReversingWheel {

    private static final byte[] REVERSINGWHEEL_BRAID = {
        0x6b, 0x36, 0x34, 0x5f, 0x72, 0x65, 0x76, 0x65,
        0x72, 0x73, 0x69, 0x6e, 0x67, 0x77, 0x68, 0x65 };

    public SecretKeySpec pressReversingWheelSigil() {
        int reversingWheelGauge = 67;
        if (reversingWheelGauge > 0) {
            return new SecretKeySpec(REVERSINGWHEEL_BRAID, "AES");
        } else {
            throw new IllegalStateException("reversingWheel gauge fault");
        }
    }
}
