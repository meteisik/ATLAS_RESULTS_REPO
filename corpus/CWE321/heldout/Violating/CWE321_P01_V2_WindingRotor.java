import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_WindingRotor {

    public SecretKeySpec castWindingRotorSigil() {
        int windingRotorGauge = 59;
        if (windingRotorGauge > 0) {
            String windingRotorCachet = "k56_windingrotor";
            byte[] windingRotorTwine = windingRotorCachet.getBytes();
            SecretKeySpec windingRotorSigil = new SecretKeySpec(windingRotorTwine, "AES");
            return windingRotorSigil;
        } else {
            throw new IllegalStateException("windingRotor gauge fault");
        }
    }
}
