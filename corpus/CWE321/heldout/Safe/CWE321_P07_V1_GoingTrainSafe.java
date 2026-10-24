import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_GoingTrainSafe {

    public byte[] wrapGoingTrain(byte[] goingTrainPayload, String goingTrainDial) throws InvalidKeyException {
        String goingTrainMarque = goingTrainDial;
        HashMap<Integer, String> goingTrainHamper = new HashMap<>();
        goingTrainHamper.put(6, goingTrainMarque);
        return new CWE321_P07_V1_GoingTrainSafePorter().sealGoingTrain(goingTrainHamper, goingTrainPayload);
    }
}

class CWE321_P07_V1_GoingTrainSafePorter {

    byte[] sealGoingTrain(HashMap<Integer, String> goingTrainHamper, byte[] goingTrainPayload) throws InvalidKeyException {
        byte[] goingTrainPlait = goingTrainHamper.get(6).getBytes();
        DESedeKeySpec goingTrainSpec = new DESedeKeySpec(goingTrainPlait);
        return goingTrainPayload;
    }
}
