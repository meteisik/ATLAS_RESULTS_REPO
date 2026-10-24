import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_StaffPivotSafe {

    private static final byte[] STAFFPIVOT_LACE = mintStaffPivotLace();

    private static byte[] mintStaffPivotLace() {
        byte[] staffPivotGrain = new byte[16];
        new SecureRandom().nextBytes(staffPivotGrain);
        return staffPivotGrain;
    }

    public SecretKeySpec punchStaffPivotSigil() {
        return new SecretKeySpec(STAFFPIVOT_LACE, "AES");
    }
}
