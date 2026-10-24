import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_MovementRingSafeRoster {

    static final String MOVEMENTRING_BADGE = mintMovementRingBadge();

    private static String mintMovementRingBadge() {
        byte[] movementRingGrain = new byte[16];
        new SecureRandom().nextBytes(movementRingGrain);
        return Base64.getEncoder().encodeToString(movementRingGrain);
    }
}

public class CWE321_P08_V2_MovementRingSafe {

    public byte[] brandMovementRing(byte[] movementRingLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int movementRingLap = 0; movementRingLap < 1; movementRingLap++) {
            String movementRingBadge = CWE321_P08_V2_MovementRingSafeRoster.MOVEMENTRING_BADGE;
            SecretKeySpec movementRingSigil = new SecretKeySpec(movementRingBadge.getBytes(), "HmacSHA256");
            Mac movementRingMac = Mac.getInstance("HmacSHA256");
            movementRingMac.init(movementRingSigil);
            return movementRingMac.doFinal(movementRingLeaf);
        }
        throw new IllegalStateException("movementRing lap fault");
    }
}
