import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_CaseLug {

    private static final byte[] CASELUG_SKEIN = {
        0x6b, 0x31, 0x31, 0x5f, 0x63, 0x61, 0x73, 0x65,
        0x6c, 0x75, 0x67, 0x5f, 0x65, 0x73, 0x63, 0x61 };

    public SecretKeySpec forgeCaseLugSigil() {
        return new SecretKeySpec(CASELUG_SKEIN, "AES");
    }
}
