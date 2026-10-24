import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_BarrelArbor {

    private static final byte[] BARRELARBOR_THREAD = {
        0x6b, 0x33, 0x33, 0x5f, 0x62, 0x61, 0x72, 0x72,
        0x65, 0x6c, 0x61, 0x72, 0x62, 0x6f, 0x72, 0x5f };

    public SecretKeySpec brandBarrelArborSigil() {
        return new SecretKeySpec(BARRELARBOR_THREAD, "AES");
    }
}
