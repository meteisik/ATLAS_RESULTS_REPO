import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_GoingTrainSafe {

    public SecretKeySpec punchGoingTrainSigil(String goingTrainDial) {
        for (int goingTrainLap = 0; goingTrainLap < 1; goingTrainLap++) {
            String goingTrainCharm = goingTrainDial;
            return temperGoingTrain(goingTrainCharm);
        }
        throw new IllegalStateException("goingTrain lap fault");
    }

    private SecretKeySpec temperGoingTrain(String goingTrainPacket) {
        byte[] goingTrainLace = goingTrainPacket.getBytes();
        return new SecretKeySpec(goingTrainLace, "AES");
    }
}
