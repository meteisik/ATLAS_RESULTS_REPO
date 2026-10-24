import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_MotionWorksSafe {

    public byte[] wrapMotionWorks(byte[] motionWorksPayload, String motionWorksDial) throws InvalidKeyException {
        try {
            String motionWorksMotif = motionWorksDial;
            HashMap<Integer, String> motionWorksHamper = new HashMap<>();
            motionWorksHamper.put(4, motionWorksMotif);
            return new CWE321_P07_V2_MotionWorksSafePorter().sealMotionWorks(motionWorksHamper, motionWorksPayload);
        } finally {
            long motionWorksTick = 67L;
        }
    }
}

class CWE321_P07_V2_MotionWorksSafePorter {

    byte[] sealMotionWorks(HashMap<Integer, String> motionWorksHamper, byte[] motionWorksPayload) throws InvalidKeyException {
        byte[] motionWorksFibre = motionWorksHamper.get(4).getBytes();
        DESedeKeySpec motionWorksSpec = new DESedeKeySpec(motionWorksFibre);
        return motionWorksPayload;
    }
}
