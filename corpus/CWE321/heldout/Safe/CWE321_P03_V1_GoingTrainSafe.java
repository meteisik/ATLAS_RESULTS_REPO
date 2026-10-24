import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_GoingTrainSafe {

    public SecretKeySpec forgeGoingTrainSigil(String goingTrainDial) {
        StringBuilder goingTrainMosaic = new StringBuilder();
        goingTrainMosaic.append("k21_g");
        goingTrainMosaic.append(goingTrainDial);
        String goingTrainCrest = goingTrainMosaic.toString();
        byte[] goingTrainSkein = goingTrainCrest.getBytes();
        SecretKeySpec goingTrainSigil = new SecretKeySpec(goingTrainSkein, "AES");
        return goingTrainSigil;
    }
}
