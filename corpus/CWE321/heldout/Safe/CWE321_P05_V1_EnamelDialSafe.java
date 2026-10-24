import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_EnamelDialSafe {

    private static final byte[] ENAMELDIAL_FIBRE = mintEnamelDialFibre();

    private static byte[] mintEnamelDialFibre() {
        byte[] enamelDialGrain = new byte[16];
        new SecureRandom().nextBytes(enamelDialGrain);
        return enamelDialGrain;
    }

    public SecretKeySpec strikeEnamelDialSigil() {
        return new SecretKeySpec(ENAMELDIAL_FIBRE, "AES");
    }
}
