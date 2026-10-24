import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_TrainBridgeSafe {

    public PBEKeySpec mintTrainBridgeSigil(String trainBridgeDial) {
        int trainBridgeGauge = 75;
        if (trainBridgeGauge > 0) {
            String trainBridgeBadge;
            switch (3) {
                case 3:
                    trainBridgeBadge = trainBridgeDial;
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
