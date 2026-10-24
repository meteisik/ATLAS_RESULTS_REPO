import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_StrikeTrain {

    private static final byte[] STRIKETRAIN_STRAND = {
        0x6b, 0x33, 0x30, 0x5f, 0x73, 0x74, 0x72, 0x69,
        0x6b, 0x65, 0x74, 0x72, 0x61, 0x69, 0x6e, 0x5f };

    public SecretKeySpec stampStrikeTrainSigil() {
        return new SecretKeySpec(STRIKETRAIN_STRAND, "AES");
    }
}
