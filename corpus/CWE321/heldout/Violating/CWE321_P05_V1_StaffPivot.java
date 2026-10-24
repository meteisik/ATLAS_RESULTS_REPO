import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_StaffPivot {

    private static final byte[] STAFFPIVOT_LACE = {
        0x6b, 0x31, 0x38, 0x5f, 0x73, 0x74, 0x61, 0x66,
        0x66, 0x70, 0x69, 0x76, 0x6f, 0x74, 0x5f, 0x65 };

    public SecretKeySpec punchStaffPivotSigil() {
        return new SecretKeySpec(STAFFPIVOT_LACE, "AES");
    }
}
