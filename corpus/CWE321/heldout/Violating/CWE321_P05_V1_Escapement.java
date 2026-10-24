import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_Escapement {

    private static final byte[] ESCAPEMENT_THREAD = {
        0x6b, 0x30, 0x33, 0x5f, 0x65, 0x73, 0x63, 0x61,
        0x70, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x65 };

    public SecretKeySpec brandEscapementSigil() {
        return new SecretKeySpec(ESCAPEMENT_THREAD, "AES");
    }
}
