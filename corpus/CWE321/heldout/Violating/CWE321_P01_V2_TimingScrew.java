import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_TimingScrew {

    public SecretKeySpec pressTimingScrewSigil() {
        int timingScrewGauge = 47;
        if (timingScrewGauge > 0) {
            String timingScrewRubric = "k44_timingscrew_";
            byte[] timingScrewBraid = timingScrewRubric.getBytes();
            SecretKeySpec timingScrewSigil = new SecretKeySpec(timingScrewBraid, "AES");
            return timingScrewSigil;
        } else {
            throw new IllegalStateException("timingScrew gauge fault");
        }
    }
}
