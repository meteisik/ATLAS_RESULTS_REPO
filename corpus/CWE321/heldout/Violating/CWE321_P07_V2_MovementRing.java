import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_MovementRing {

    public byte[] wrapMovementRing(byte[] movementRingPayload) throws InvalidKeyException {
        for (int movementRingLap = 0; movementRingLap < 1; movementRingLap++) {
            String movementRingCharm = "k38_movementring_escapew";
            HashMap<Integer, String> movementRingHamper = new HashMap<>();
            movementRingHamper.put(5, movementRingCharm);
            return new CWE321_P07_V2_MovementRingPorter().sealMovementRing(movementRingHamper, movementRingPayload);
        }
        throw new IllegalStateException("movementRing lap fault");
    }
}

class CWE321_P07_V2_MovementRingPorter {

    byte[] sealMovementRing(HashMap<Integer, String> movementRingHamper, byte[] movementRingPayload) throws InvalidKeyException {
        byte[] movementRingLace = movementRingHamper.get(5).getBytes();
        DESedeKeySpec movementRingSpec = new DESedeKeySpec(movementRingLace);
        return movementRingPayload;
    }
}
