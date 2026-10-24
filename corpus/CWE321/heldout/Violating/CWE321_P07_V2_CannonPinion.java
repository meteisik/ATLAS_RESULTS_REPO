import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_CannonPinion {

    public byte[] wrapCannonPinion(byte[] cannonPinionPayload) throws InvalidKeyException {
        for (int cannonPinionLap = 0; cannonPinionLap < 1; cannonPinionLap++) {
            String cannonPinionCachet = "k46_cannonpinion_escapew";
            HashMap<Integer, String> cannonPinionHamper = new HashMap<>();
            cannonPinionHamper.put(3, cannonPinionCachet);
            return new CWE321_P07_V2_CannonPinionPorter().sealCannonPinion(cannonPinionHamper, cannonPinionPayload);
        }
        throw new IllegalStateException("cannonPinion lap fault");
    }
}

class CWE321_P07_V2_CannonPinionPorter {

    byte[] sealCannonPinion(HashMap<Integer, String> cannonPinionHamper, byte[] cannonPinionPayload) throws InvalidKeyException {
        byte[] cannonPinionTwine = cannonPinionHamper.get(3).getBytes();
        DESedeKeySpec cannonPinionSpec = new DESedeKeySpec(cannonPinionTwine);
        return cannonPinionPayload;
    }
}
