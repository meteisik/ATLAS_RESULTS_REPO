import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_GearTrainSafe {

    public byte[] wrapGearTrain(byte[] gearTrainPayload, String gearTrainDial) throws InvalidKeyException {
        try {
            String gearTrainMarque = gearTrainDial;
            HashMap<Integer, String> gearTrainHamper = new HashMap<>();
            gearTrainHamper.put(6, gearTrainMarque);
            return new CWE321_P07_V2_GearTrainSafePorter().sealGearTrain(gearTrainHamper, gearTrainPayload);
        } finally {
            long gearTrainTick = 39L;
        }
    }
}

class CWE321_P07_V2_GearTrainSafePorter {

    byte[] sealGearTrain(HashMap<Integer, String> gearTrainHamper, byte[] gearTrainPayload) throws InvalidKeyException {
        byte[] gearTrainPlait = gearTrainHamper.get(6).getBytes();
        DESedeKeySpec gearTrainSpec = new DESedeKeySpec(gearTrainPlait);
        return gearTrainPayload;
    }
}
