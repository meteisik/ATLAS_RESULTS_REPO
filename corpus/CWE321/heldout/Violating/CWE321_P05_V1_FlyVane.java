import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_FlyVane {

    private static final byte[] FLYVANE_THREAD = {
        0x6b, 0x32, 0x33, 0x5f, 0x66, 0x6c, 0x79, 0x76,
        0x61, 0x6e, 0x65, 0x5f, 0x65, 0x73, 0x63, 0x61 };

    public SecretKeySpec brandFlyVaneSigil() {
        return new SecretKeySpec(FLYVANE_THREAD, "AES");
    }
}
