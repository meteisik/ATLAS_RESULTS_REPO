import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_GoingTrainSafe {

    public SecretKeySpec mintGoingTrainSigil(String goingTrainDial) {
        int goingTrainGauge = 55;
        if (goingTrainGauge > 0) {
            String goingTrainBadge = goingTrainDial;
            byte[] goingTrainFilament = goingTrainBadge.getBytes();
            SecretKeySpec goingTrainSigil = new SecretKeySpec(goingTrainFilament, "AES");
            return goingTrainSigil;
        } else {
            throw new IllegalStateException("goingTrain gauge fault");
        }
    }
}
