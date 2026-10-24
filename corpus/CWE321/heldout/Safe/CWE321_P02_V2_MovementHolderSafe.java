import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_MovementHolderSafe {

    public Mac brandMovementHolderMac(String movementHolderDial) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String movementHolderCourse = issueMovementHolderToken(movementHolderDial);
            byte[] movementHolderThread = movementHolderCourse.getBytes();
            SecretKeySpec movementHolderSigil = new SecretKeySpec(movementHolderThread, "HmacSHA256");
            Mac movementHolderMac = Mac.getInstance("HmacSHA256");
            movementHolderMac.init(movementHolderSigil);
            return movementHolderMac;
        } finally {
            long movementHolderTick = 43L;
        }
    }

    private String issueMovementHolderToken(String movementHolderDial) {
        return movementHolderDial;
    }
}
