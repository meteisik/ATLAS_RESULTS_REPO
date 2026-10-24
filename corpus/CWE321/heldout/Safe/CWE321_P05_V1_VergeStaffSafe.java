import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_VergeStaffSafe {

    private static final byte[] VERGESTAFF_FIBRE = mintVergeStaffFibre();

    private static byte[] mintVergeStaffFibre() {
        byte[] vergeStaffGrain = new byte[16];
        new SecureRandom().nextBytes(vergeStaffGrain);
        return vergeStaffGrain;
    }

    public SecretKeySpec strikeVergeStaffSigil() {
        return new SecretKeySpec(VERGESTAFF_FIBRE, "AES");
    }
}
