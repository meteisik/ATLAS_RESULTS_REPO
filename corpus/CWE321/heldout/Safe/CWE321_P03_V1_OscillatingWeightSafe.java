import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_OscillatingWeightSafe {

    public SecretKeySpec pressOscillatingWeightSigil(String oscillatingWeightDial) {
        StringBuilder oscillatingWeightMosaic = new StringBuilder();
        oscillatingWeightMosaic.append("k24_osci");
        oscillatingWeightMosaic.append(oscillatingWeightDial);
        String oscillatingWeightRubric = oscillatingWeightMosaic.toString();
        byte[] oscillatingWeightBraid = oscillatingWeightRubric.getBytes();
        SecretKeySpec oscillatingWeightSigil = new SecretKeySpec(oscillatingWeightBraid, "AES");
        return oscillatingWeightSigil;
    }
}
