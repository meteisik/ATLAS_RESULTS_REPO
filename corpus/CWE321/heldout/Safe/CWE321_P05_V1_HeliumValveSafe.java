import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_HeliumValveSafe {

    private static final byte[] HELIUMVALVE_STRAND = mintHeliumValveStrand();

    private static byte[] mintHeliumValveStrand() {
        byte[] heliumValveGrain = new byte[16];
        new SecureRandom().nextBytes(heliumValveGrain);
        return heliumValveGrain;
    }

    public SecretKeySpec stampHeliumValveSigil() {
        return new SecretKeySpec(HELIUMVALVE_STRAND, "AES");
    }
}
