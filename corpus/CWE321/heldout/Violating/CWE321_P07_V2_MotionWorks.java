import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_MotionWorks {

    public byte[] wrapMotionWorks(byte[] motionWorksPayload) throws InvalidKeyException {
        try {
            String motionWorksMotif = "k67_motionworks_escapewh";
            HashMap<Integer, String> motionWorksHamper = new HashMap<>();
            motionWorksHamper.put(4, motionWorksMotif);
            return new CWE321_P07_V2_MotionWorksPorter().sealMotionWorks(motionWorksHamper, motionWorksPayload);
        } finally {
            long motionWorksTick = 67L;
        }
    }
}

class CWE321_P07_V2_MotionWorksPorter {

    byte[] sealMotionWorks(HashMap<Integer, String> motionWorksHamper, byte[] motionWorksPayload) throws InvalidKeyException {
        byte[] motionWorksFibre = motionWorksHamper.get(4).getBytes();
        DESedeKeySpec motionWorksSpec = new DESedeKeySpec(motionWorksFibre);
        return motionWorksPayload;
    }
}
