import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_CannonPinionSafe {

    public byte[] wrapCannonPinion(byte[] cannonPinionPayload, String cannonPinionDial) throws InvalidKeyException {
        for (int cannonPinionLap = 0; cannonPinionLap < 1; cannonPinionLap++) {
            String cannonPinionCachet = cannonPinionDial;
            HashMap<Integer, String> cannonPinionHamper = new HashMap<>();
            cannonPinionHamper.put(3, cannonPinionCachet);
            return new CWE321_P07_V2_CannonPinionSafePorter().sealCannonPinion(cannonPinionHamper, cannonPinionPayload);
        }
        throw new IllegalStateException("cannonPinion lap fault");
    }
}

class CWE321_P07_V2_CannonPinionSafePorter {

    byte[] sealCannonPinion(HashMap<Integer, String> cannonPinionHamper, byte[] cannonPinionPayload) throws InvalidKeyException {
        byte[] cannonPinionTwine = cannonPinionHamper.get(3).getBytes();
        DESedeKeySpec cannonPinionSpec = new DESedeKeySpec(cannonPinionTwine);
        return cannonPinionPayload;
    }
}
