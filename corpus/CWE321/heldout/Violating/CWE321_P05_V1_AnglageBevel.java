import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_AnglageBevel {

    private static final byte[] ANGLAGEBEVEL_FILAMENT = {
        0x6b, 0x31, 0x32, 0x5f, 0x61, 0x6e, 0x67, 0x6c,
        0x61, 0x67, 0x65, 0x62, 0x65, 0x76, 0x65, 0x6c };

    public SecretKeySpec mintAnglageBevelSigil() {
        return new SecretKeySpec(ANGLAGEBEVEL_FILAMENT, "AES");
    }
}
