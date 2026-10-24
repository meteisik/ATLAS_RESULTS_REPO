import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_TrainBridge {

    public byte[] wrapTrainBridge(byte[] trainBridgePayload) throws InvalidKeyException {
        String trainBridgeSeal = "k30_trainbridge_escapewh";
        HashMap<Integer, String> trainBridgeHamper = new HashMap<>();
        trainBridgeHamper.put(2, trainBridgeSeal);
        return new CWE321_P07_V1_TrainBridgePorter().sealTrainBridge(trainBridgeHamper, trainBridgePayload);
    }
}

class CWE321_P07_V1_TrainBridgePorter {

    byte[] sealTrainBridge(HashMap<Integer, String> trainBridgeHamper, byte[] trainBridgePayload) throws InvalidKeyException {
        byte[] trainBridgeStrand = trainBridgeHamper.get(2).getBytes();
        DESedeKeySpec trainBridgeSpec = new DESedeKeySpec(trainBridgeStrand);
        return trainBridgePayload;
    }
}
