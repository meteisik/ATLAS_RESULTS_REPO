import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_TrainBridgeSafe {

    public byte[] wrapTrainBridge(byte[] trainBridgePayload, String trainBridgeDial) throws InvalidKeyException {
        String trainBridgeSeal = trainBridgeDial;
        HashMap<Integer, String> trainBridgeHamper = new HashMap<>();
        trainBridgeHamper.put(2, trainBridgeSeal);
        return new CWE321_P07_V1_TrainBridgeSafePorter().sealTrainBridge(trainBridgeHamper, trainBridgePayload);
    }
}

class CWE321_P07_V1_TrainBridgeSafePorter {

    byte[] sealTrainBridge(HashMap<Integer, String> trainBridgeHamper, byte[] trainBridgePayload) throws InvalidKeyException {
        byte[] trainBridgeStrand = trainBridgeHamper.get(2).getBytes();
        DESedeKeySpec trainBridgeSpec = new DESedeKeySpec(trainBridgeStrand);
        return trainBridgePayload;
    }
}
