import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_TrainBridge {

    public PBEKeySpec mintTrainBridgeSigil() {
        int trainBridgeGauge = 75;
        if (trainBridgeGauge > 0) {
            String trainBridgeBadge;
            switch (3) {
                case 3:
                    trainBridgeBadge = "k72_trainbridge_";
                    break;
                default:
                    trainBridgeBadge = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(trainBridgeBadge.toCharArray());
        } else {
            throw new IllegalStateException("trainBridge gauge fault");
        }
    }
}
