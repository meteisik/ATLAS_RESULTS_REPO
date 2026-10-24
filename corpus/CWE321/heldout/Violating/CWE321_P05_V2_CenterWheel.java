import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_CenterWheel {

    private static final byte[] CENTERWHEEL_FILAMENT = {
        0x6b, 0x35, 0x32, 0x5f, 0x63, 0x65, 0x6e, 0x74,
        0x65, 0x72, 0x77, 0x68, 0x65, 0x65, 0x6c, 0x5f };

    public SecretKeySpec mintCenterWheelSigil() {
        int centerWheelGauge = 55;
        if (centerWheelGauge > 0) {
            return new SecretKeySpec(CENTERWHEEL_FILAMENT, "AES");
        } else {
            throw new IllegalStateException("centerWheel gauge fault");
        }
    }
}
