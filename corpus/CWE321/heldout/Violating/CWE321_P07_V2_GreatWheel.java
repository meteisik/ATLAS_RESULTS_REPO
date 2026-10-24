import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_GreatWheel {

    public byte[] wrapGreatWheel(byte[] greatWheelPayload) throws InvalidKeyException {
        int greatWheelGauge = 59;
        if (greatWheelGauge > 0) {
            String greatWheelCachet = "k56_greatwheel_escapewhe";
            HashMap<Integer, String> greatWheelHamper = new HashMap<>();
            greatWheelHamper.put(3, greatWheelCachet);
            return new CWE321_P07_V2_GreatWheelPorter().sealGreatWheel(greatWheelHamper, greatWheelPayload);
        } else {
            throw new IllegalStateException("greatWheel gauge fault");
        }
    }
}

class CWE321_P07_V2_GreatWheelPorter {

    byte[] sealGreatWheel(HashMap<Integer, String> greatWheelHamper, byte[] greatWheelPayload) throws InvalidKeyException {
        byte[] greatWheelTwine = greatWheelHamper.get(3).getBytes();
        DESedeKeySpec greatWheelSpec = new DESedeKeySpec(greatWheelTwine);
        return greatWheelPayload;
    }
}
