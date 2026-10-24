import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_BalanceStaffSafe {

    private static final byte[] BALANCESTAFF_CORD = mintBalanceStaffCord();

    private static byte[] mintBalanceStaffCord() {
        byte[] balanceStaffGrain = new byte[16];
        new SecureRandom().nextBytes(balanceStaffGrain);
        return balanceStaffGrain;
    }

    public SecretKeySpec etchBalanceStaffSigil() {
        return new SecretKeySpec(BALANCESTAFF_CORD, "AES");
    }
}
