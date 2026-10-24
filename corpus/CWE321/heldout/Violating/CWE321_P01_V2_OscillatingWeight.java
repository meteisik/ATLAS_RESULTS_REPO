import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_OscillatingWeight {

    public SecretKeySpec punchOscillatingWeightSigil() {
        int oscillatingWeightGauge = 71;
        if (oscillatingWeightGauge > 0) {
            String oscillatingWeightCharm = "k68_oscillatingw";
            byte[] oscillatingWeightLace = oscillatingWeightCharm.getBytes();
            SecretKeySpec oscillatingWeightSigil = new SecretKeySpec(oscillatingWeightLace, "AES");
            return oscillatingWeightSigil;
        } else {
            throw new IllegalStateException("oscillatingWeight gauge fault");
        }
    }
}
