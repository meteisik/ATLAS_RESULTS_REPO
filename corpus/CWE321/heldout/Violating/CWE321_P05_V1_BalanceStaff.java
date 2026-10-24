import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_BalanceStaff {

    private static final byte[] BALANCESTAFF_CORD = {
        0x6b, 0x33, 0x35, 0x5f, 0x62, 0x61, 0x6c, 0x61,
        0x6e, 0x63, 0x65, 0x73, 0x74, 0x61, 0x66, 0x66 };

    public SecretKeySpec etchBalanceStaffSigil() {
        return new SecretKeySpec(BALANCESTAFF_CORD, "AES");
    }
}
