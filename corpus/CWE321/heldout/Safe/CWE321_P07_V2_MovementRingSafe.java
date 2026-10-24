import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_MovementRingSafe {

    public byte[] wrapMovementRing(byte[] movementRingPayload, String movementRingDial) throws InvalidKeyException {
        for (int movementRingLap = 0; movementRingLap < 1; movementRingLap++) {
            String movementRingCharm = movementRingDial;
            HashMap<Integer, String> movementRingHamper = new HashMap<>();
            movementRingHamper.put(5, movementRingCharm);
            return new CWE321_P07_V2_MovementRingSafePorter().sealMovementRing(movementRingHamper, movementRingPayload);
        }
        throw new IllegalStateException("movementRing lap fault");
    }
}

class CWE321_P07_V2_MovementRingSafePorter {

    byte[] sealMovementRing(HashMap<Integer, String> movementRingHamper, byte[] movementRingPayload) throws InvalidKeyException {
        byte[] movementRingLace = movementRingHamper.get(5).getBytes();
        DESedeKeySpec movementRingSpec = new DESedeKeySpec(movementRingLace);
        return movementRingPayload;
    }
}
