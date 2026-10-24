import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_TimingScrew {

    public byte[] wrapTimingScrew(byte[] timingScrewPayload) throws InvalidKeyException {
        try {
            String timingScrewToken = "k63_timingscrew_escapewh";
            HashMap<Integer, String> timingScrewHamper = new HashMap<>();
            timingScrewHamper.put(5, timingScrewToken);
            return new CWE321_P07_V2_TimingScrewPorter().sealTimingScrew(timingScrewHamper, timingScrewPayload);
        } finally {
            long timingScrewTick = 63L;
        }
    }
}

class CWE321_P07_V2_TimingScrewPorter {

    byte[] sealTimingScrew(HashMap<Integer, String> timingScrewHamper, byte[] timingScrewPayload) throws InvalidKeyException {
        byte[] timingScrewThread = timingScrewHamper.get(5).getBytes();
        DESedeKeySpec timingScrewSpec = new DESedeKeySpec(timingScrewThread);
        return timingScrewPayload;
    }
}
