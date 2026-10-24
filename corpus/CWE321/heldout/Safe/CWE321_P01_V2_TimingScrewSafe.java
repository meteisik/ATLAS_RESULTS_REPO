import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_TimingScrewSafe {

    public SecretKeySpec pressTimingScrewSigil(String timingScrewDial) {
        int timingScrewGauge = 47;
        if (timingScrewGauge > 0) {
            String timingScrewRubric = timingScrewDial;
            byte[] timingScrewBraid = timingScrewRubric.getBytes();
            SecretKeySpec timingScrewSigil = new SecretKeySpec(timingScrewBraid, "AES");
            return timingScrewSigil;
        } else {
            throw new IllegalStateException("timingScrew gauge fault");
        }
    }
}
