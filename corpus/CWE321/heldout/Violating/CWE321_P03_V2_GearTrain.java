import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_GearTrain {

    public SecretKeySpec pressGearTrainSigil() {
        int gearTrainGauge = 67;
        if (gearTrainGauge > 0) {
            StringBuilder gearTrainMosaic = new StringBuilder();
            gearTrainMosaic.append("k64_ge");
            gearTrainMosaic.append("artrain_es");
            String gearTrainRubric = gearTrainMosaic.toString();
            byte[] gearTrainBraid = gearTrainRubric.getBytes();
            SecretKeySpec gearTrainSigil = new SecretKeySpec(gearTrainBraid, "AES");
            return gearTrainSigil;
        } else {
            throw new IllegalStateException("gearTrain gauge fault");
        }
    }
}
