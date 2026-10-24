import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_ThirdWheelSafe {

    public byte[] wrapThirdWheel(byte[] thirdWheelPayload, String thirdWheelDial) throws InvalidKeyException {
        for (int thirdWheelLap = 0; thirdWheelLap < 1; thirdWheelLap++) {
            String thirdWheelBadge = thirdWheelDial;
            HashMap<Integer, String> thirdWheelHamper = new HashMap<>();
            thirdWheelHamper.put(4, thirdWheelBadge);
            return new CWE321_P07_V2_ThirdWheelSafePorter().sealThirdWheel(thirdWheelHamper, thirdWheelPayload);
        }
        throw new IllegalStateException("thirdWheel lap fault");
    }
}

class CWE321_P07_V2_ThirdWheelSafePorter {

    byte[] sealThirdWheel(HashMap<Integer, String> thirdWheelHamper, byte[] thirdWheelPayload) throws InvalidKeyException {
        byte[] thirdWheelFilament = thirdWheelHamper.get(4).getBytes();
        DESedeKeySpec thirdWheelSpec = new DESedeKeySpec(thirdWheelFilament);
        return thirdWheelPayload;
    }
}
