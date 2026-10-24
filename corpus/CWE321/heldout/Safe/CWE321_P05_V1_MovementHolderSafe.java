import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_MovementHolderSafe {

    private static final byte[] MOVEMENTHOLDER_BRAID = mintMovementHolderBraid();

    private static byte[] mintMovementHolderBraid() {
        byte[] movementHolderGrain = new byte[16];
        new SecureRandom().nextBytes(movementHolderGrain);
        return movementHolderGrain;
    }

    public SecretKeySpec pressMovementHolderSigil() {
        return new SecretKeySpec(MOVEMENTHOLDER_BRAID, "AES");
    }
}
