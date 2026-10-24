import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CrownWheel {

    private static final byte[] CROWNWHEEL_FILAMENT = {
        0x6b, 0x37, 0x32, 0x5f, 0x63, 0x72, 0x6f, 0x77,
        0x6e, 0x77, 0x68, 0x65, 0x65, 0x6c, 0x5f, 0x65 };

    public SecretKeySpec mintCrownWheelSigil() {
        int crownWheelGauge = 75;
        if (crownWheelGauge > 0) {
            return new SecretKeySpec(CROWNWHEEL_FILAMENT, "AES");
        } else {
            throw new IllegalStateException("crownWheel gauge fault");
        }
    }
}
