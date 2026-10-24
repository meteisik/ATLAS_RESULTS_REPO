import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_PillarPlateSafe {

    private static final byte[] PILLARPLATE_FIBRE = mintPillarPlateFibre();

    private static byte[] mintPillarPlateFibre() {
        byte[] pillarPlateGrain = new byte[16];
        new SecureRandom().nextBytes(pillarPlateGrain);
        return pillarPlateGrain;
    }

    public SecretKeySpec strikePillarPlateSigil() {
        return new SecretKeySpec(PILLARPLATE_FIBRE, "AES");
    }
}
