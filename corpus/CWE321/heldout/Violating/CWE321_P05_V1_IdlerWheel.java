import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_IdlerWheel {

    private static final byte[] IDLERWHEEL_FILAMENT = {
        0x6b, 0x33, 0x32, 0x5f, 0x69, 0x64, 0x6c, 0x65,
        0x72, 0x77, 0x68, 0x65, 0x65, 0x6c, 0x5f, 0x65 };

    public SecretKeySpec mintIdlerWheelSigil() {
        return new SecretKeySpec(IDLERWHEEL_FILAMENT, "AES");
    }
}
