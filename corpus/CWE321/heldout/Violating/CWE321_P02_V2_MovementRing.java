import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_MovementRing {

    public Mac brandMovementRingMac() throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String movementRingCourse = issueMovementRingToken();
            byte[] movementRingThread = movementRingCourse.getBytes();
            SecretKeySpec movementRingSigil = new SecretKeySpec(movementRingThread, "HmacSHA256");
            Mac movementRingMac = Mac.getInstance("HmacSHA256");
            movementRingMac.init(movementRingSigil);
            return movementRingMac;
        } finally {
            long movementRingTick = 63L;
        }
    }

    private String issueMovementRingToken() {
        return "k63_movementring";
    }
}
