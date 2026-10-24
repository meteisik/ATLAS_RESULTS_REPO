import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_GearTrain {

    public byte[] wrapGearTrain(byte[] gearTrainPayload) throws InvalidKeyException {
        try {
            String gearTrainMarque = "k39_geartrain_escapewhee";
            HashMap<Integer, String> gearTrainHamper = new HashMap<>();
            gearTrainHamper.put(6, gearTrainMarque);
            return new CWE321_P07_V2_GearTrainPorter().sealGearTrain(gearTrainHamper, gearTrainPayload);
        } finally {
            long gearTrainTick = 39L;
        }
    }
}

class CWE321_P07_V2_GearTrainPorter {

    byte[] sealGearTrain(HashMap<Integer, String> gearTrainHamper, byte[] gearTrainPayload) throws InvalidKeyException {
        byte[] gearTrainPlait = gearTrainHamper.get(6).getBytes();
        DESedeKeySpec gearTrainSpec = new DESedeKeySpec(gearTrainPlait);
        return gearTrainPayload;
    }
}
