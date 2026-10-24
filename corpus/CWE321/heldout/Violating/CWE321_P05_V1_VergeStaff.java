import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_VergeStaff {

    private static final byte[] VERGESTAFF_FIBRE = {
        0x6b, 0x32, 0x37, 0x5f, 0x76, 0x65, 0x72, 0x67,
        0x65, 0x73, 0x74, 0x61, 0x66, 0x66, 0x5f, 0x65 };

    public SecretKeySpec strikeVergeStaffSigil() {
        return new SecretKeySpec(VERGESTAFF_FIBRE, "AES");
    }
}
