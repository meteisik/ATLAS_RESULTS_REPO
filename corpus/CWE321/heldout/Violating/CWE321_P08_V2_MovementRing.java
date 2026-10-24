import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_MovementRingRoster {

    static final String MOVEMENTRING_BADGE = "k42_movementring";
}

public class CWE321_P08_V2_MovementRing {

    public byte[] brandMovementRing(byte[] movementRingLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int movementRingLap = 0; movementRingLap < 1; movementRingLap++) {
            String movementRingBadge = CWE321_P08_V2_MovementRingRoster.MOVEMENTRING_BADGE;
            SecretKeySpec movementRingSigil = new SecretKeySpec(movementRingBadge.getBytes(), "HmacSHA256");
            Mac movementRingMac = Mac.getInstance("HmacSHA256");
            movementRingMac.init(movementRingSigil);
            return movementRingMac.doFinal(movementRingLeaf);
        }
        throw new IllegalStateException("movementRing lap fault");
    }
}
