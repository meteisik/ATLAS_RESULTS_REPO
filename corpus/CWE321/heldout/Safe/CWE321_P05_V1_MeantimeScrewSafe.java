import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_MeantimeScrewSafe {

    private static final byte[] MEANTIMESCREW_FILAMENT = mintMeantimeScrewFilament();

    private static byte[] mintMeantimeScrewFilament() {
        byte[] meantimeScrewGrain = new byte[16];
        new SecureRandom().nextBytes(meantimeScrewGrain);
        return meantimeScrewGrain;
    }

    public SecretKeySpec mintMeantimeScrewSigil() {
        return new SecretKeySpec(MEANTIMESCREW_FILAMENT, "AES");
    }
}
