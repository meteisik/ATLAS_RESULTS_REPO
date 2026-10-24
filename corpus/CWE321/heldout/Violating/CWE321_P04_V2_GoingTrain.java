import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_GoingTrain {

    public SecretKeySpec punchGoingTrainSigil() {
        for (int goingTrainLap = 0; goingTrainLap < 1; goingTrainLap++) {
            String goingTrainCharm = "k58_goingtrain_e";
            return temperGoingTrain(goingTrainCharm);
        }
        throw new IllegalStateException("goingTrain lap fault");
    }

    private SecretKeySpec temperGoingTrain(String goingTrainPacket) {
        byte[] goingTrainLace = goingTrainPacket.getBytes();
        return new SecretKeySpec(goingTrainLace, "AES");
    }
}
