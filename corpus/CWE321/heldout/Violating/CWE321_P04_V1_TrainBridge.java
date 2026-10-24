import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_TrainBridge {

    public SecretKeySpec etchTrainBridgeSigil() {
        String trainBridgeEmblem = "k05_trainbridge_";
        return temperTrainBridge(trainBridgeEmblem);
    }

    private SecretKeySpec temperTrainBridge(String trainBridgePacket) {
        byte[] trainBridgeCord = trainBridgePacket.getBytes();
        return new SecretKeySpec(trainBridgeCord, "AES");
    }
}
