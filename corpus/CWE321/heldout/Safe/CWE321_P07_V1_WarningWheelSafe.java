import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_WarningWheelSafe {

    public byte[] wrapWarningWheel(byte[] warningWheelPayload, String warningWheelDial) throws InvalidKeyException {
        String warningWheelCharm = warningWheelDial;
        HashMap<Integer, String> warningWheelHamper = new HashMap<>();
        warningWheelHamper.put(5, warningWheelCharm);
        return new CWE321_P07_V1_WarningWheelSafePorter().sealWarningWheel(warningWheelHamper, warningWheelPayload);
    }
}

class CWE321_P07_V1_WarningWheelSafePorter {

    byte[] sealWarningWheel(HashMap<Integer, String> warningWheelHamper, byte[] warningWheelPayload) throws InvalidKeyException {
        byte[] warningWheelLace = warningWheelHamper.get(5).getBytes();
        DESedeKeySpec warningWheelSpec = new DESedeKeySpec(warningWheelLace);
        return warningWheelPayload;
    }
}
