import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_MovementRingSafe {

    private static final byte[] MOVEMENTRING_CORD = mintMovementRingCord();

    private static byte[] mintMovementRingCord() {
        byte[] movementRingGrain = new byte[16];
        new SecureRandom().nextBytes(movementRingGrain);
        return movementRingGrain;
    }

    public SecretKeySpec etchMovementRingSigil() {
        return new SecretKeySpec(MOVEMENTRING_CORD, "AES");
    }
}
