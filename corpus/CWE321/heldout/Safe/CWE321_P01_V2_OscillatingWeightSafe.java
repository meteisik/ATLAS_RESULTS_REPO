import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_OscillatingWeightSafe {

    public SecretKeySpec punchOscillatingWeightSigil(String oscillatingWeightDial) {
        int oscillatingWeightGauge = 71;
        if (oscillatingWeightGauge > 0) {
            String oscillatingWeightCharm = oscillatingWeightDial;
            byte[] oscillatingWeightLace = oscillatingWeightCharm.getBytes();
            SecretKeySpec oscillatingWeightSigil = new SecretKeySpec(oscillatingWeightLace, "AES");
            return oscillatingWeightSigil;
        } else {
            throw new IllegalStateException("oscillatingWeight gauge fault");
        }
    }
}
