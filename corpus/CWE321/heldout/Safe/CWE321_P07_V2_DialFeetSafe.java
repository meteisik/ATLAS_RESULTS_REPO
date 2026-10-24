import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_DialFeetSafe {

    public byte[] wrapDialFeet(byte[] dialFeetPayload, String dialFeetDial) throws InvalidKeyException {
        int dialFeetGauge = 71;
        if (dialFeetGauge > 0) {
            String dialFeetCharm = dialFeetDial;
            HashMap<Integer, String> dialFeetHamper = new HashMap<>();
            dialFeetHamper.put(5, dialFeetCharm);
            return new CWE321_P07_V2_DialFeetSafePorter().sealDialFeet(dialFeetHamper, dialFeetPayload);
        } else {
            throw new IllegalStateException("dialFeet gauge fault");
        }
    }
}

class CWE321_P07_V2_DialFeetSafePorter {

    byte[] sealDialFeet(HashMap<Integer, String> dialFeetHamper, byte[] dialFeetPayload) throws InvalidKeyException {
        byte[] dialFeetLace = dialFeetHamper.get(5).getBytes();
        DESedeKeySpec dialFeetSpec = new DESedeKeySpec(dialFeetLace);
        return dialFeetPayload;
    }
}
