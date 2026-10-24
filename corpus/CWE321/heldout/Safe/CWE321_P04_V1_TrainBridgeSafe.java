import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_TrainBridgeSafe {

    public SecretKeySpec etchTrainBridgeSigil(String trainBridgeDial) {
        String trainBridgeEmblem = trainBridgeDial;
        return temperTrainBridge(trainBridgeEmblem);
    }

    private SecretKeySpec temperTrainBridge(String trainBridgePacket) {
        byte[] trainBridgeCord = trainBridgePacket.getBytes();
        return new SecretKeySpec(trainBridgeCord, "AES");
    }
}
