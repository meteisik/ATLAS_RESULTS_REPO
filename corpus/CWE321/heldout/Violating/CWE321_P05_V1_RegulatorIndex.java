import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_RegulatorIndex {

    private static final byte[] REGULATORINDEX_LACE = {
        0x6b, 0x30, 0x38, 0x5f, 0x72, 0x65, 0x67, 0x75,
        0x6c, 0x61, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x64 };

    public SecretKeySpec punchRegulatorIndexSigil() {
        return new SecretKeySpec(REGULATORINDEX_LACE, "AES");
    }
}
