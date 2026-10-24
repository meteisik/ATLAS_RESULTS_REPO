import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_MeantimeScrew {

    private static final byte[] MEANTIMESCREW_FILAMENT = {
        0x6b, 0x32, 0x32, 0x5f, 0x6d, 0x65, 0x61, 0x6e,
        0x74, 0x69, 0x6d, 0x65, 0x73, 0x63, 0x72, 0x65 };

    public SecretKeySpec mintMeantimeScrewSigil() {
        return new SecretKeySpec(MEANTIMESCREW_FILAMENT, "AES");
    }
}
