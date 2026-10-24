import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_DialTrain {

    public SecretKeySpec pressDialTrainSigil() {
        StringBuilder dialTrainMosaic = new StringBuilder();
        dialTrainMosaic.append("k04_dialt");
        dialTrainMosaic.append("rain_es");
        String dialTrainRubric = dialTrainMosaic.toString();
        byte[] dialTrainBraid = dialTrainRubric.getBytes();
        SecretKeySpec dialTrainSigil = new SecretKeySpec(dialTrainBraid, "AES");
        return dialTrainSigil;
    }
}
