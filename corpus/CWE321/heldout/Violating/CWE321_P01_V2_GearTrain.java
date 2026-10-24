import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_GearTrain {

    public SecretKeySpec punchGearTrainSigil() {
        for (int gearTrainLap = 0; gearTrainLap < 1; gearTrainLap++) {
            String gearTrainCharm = "k38_geartrain_es";
            byte[] gearTrainLace = gearTrainCharm.getBytes();
            SecretKeySpec gearTrainSigil = new SecretKeySpec(gearTrainLace, "AES");
            return gearTrainSigil;
        }
        throw new IllegalStateException("gearTrain lap fault");
    }
}
