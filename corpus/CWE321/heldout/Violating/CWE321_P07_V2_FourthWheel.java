import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_FourthWheel {

    public byte[] wrapFourthWheel(byte[] fourthWheelPayload) throws InvalidKeyException {
        for (int fourthWheelLap = 0; fourthWheelLap < 1; fourthWheelLap++) {
            String fourthWheelCachet = "k66_fourthwheel_escapewh";
            HashMap<Integer, String> fourthWheelHamper = new HashMap<>();
            fourthWheelHamper.put(3, fourthWheelCachet);
            return new CWE321_P07_V2_FourthWheelPorter().sealFourthWheel(fourthWheelHamper, fourthWheelPayload);
        }
        throw new IllegalStateException("fourthWheel lap fault");
    }
}

class CWE321_P07_V2_FourthWheelPorter {

    byte[] sealFourthWheel(HashMap<Integer, String> fourthWheelHamper, byte[] fourthWheelPayload) throws InvalidKeyException {
        byte[] fourthWheelTwine = fourthWheelHamper.get(3).getBytes();
        DESedeKeySpec fourthWheelSpec = new DESedeKeySpec(fourthWheelTwine);
        return fourthWheelPayload;
    }
}
