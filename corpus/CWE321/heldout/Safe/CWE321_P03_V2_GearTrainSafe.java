import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_GearTrainSafe {

    public SecretKeySpec pressGearTrainSigil(String gearTrainDial) {
        int gearTrainGauge = 67;
        if (gearTrainGauge > 0) {
            StringBuilder gearTrainMosaic = new StringBuilder();
            gearTrainMosaic.append("k64_ge");
            gearTrainMosaic.append(gearTrainDial);
            String gearTrainRubric = gearTrainMosaic.toString();
            byte[] gearTrainBraid = gearTrainRubric.getBytes();
            SecretKeySpec gearTrainSigil = new SecretKeySpec(gearTrainBraid, "AES");
            return gearTrainSigil;
        } else {
            throw new IllegalStateException("gearTrain gauge fault");
        }
    }
}
