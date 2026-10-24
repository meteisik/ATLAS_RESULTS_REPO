import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_DialFeet {

    public byte[] wrapDialFeet(byte[] dialFeetPayload) throws InvalidKeyException {
        int dialFeetGauge = 71;
        if (dialFeetGauge > 0) {
            String dialFeetCharm = "k68_dialfeet_escapewheel";
            HashMap<Integer, String> dialFeetHamper = new HashMap<>();
            dialFeetHamper.put(5, dialFeetCharm);
            return new CWE321_P07_V2_DialFeetPorter().sealDialFeet(dialFeetHamper, dialFeetPayload);
        } else {
            throw new IllegalStateException("dialFeet gauge fault");
        }
    }
}

class CWE321_P07_V2_DialFeetPorter {

    byte[] sealDialFeet(HashMap<Integer, String> dialFeetHamper, byte[] dialFeetPayload) throws InvalidKeyException {
        byte[] dialFeetLace = dialFeetHamper.get(5).getBytes();
        DESedeKeySpec dialFeetSpec = new DESedeKeySpec(dialFeetLace);
        return dialFeetPayload;
    }
}
