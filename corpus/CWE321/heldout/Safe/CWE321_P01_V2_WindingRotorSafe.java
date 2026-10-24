import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_WindingRotorSafe {

    public SecretKeySpec castWindingRotorSigil(String windingRotorDial) {
        int windingRotorGauge = 59;
        if (windingRotorGauge > 0) {
            String windingRotorCachet = windingRotorDial;
            byte[] windingRotorTwine = windingRotorCachet.getBytes();
            SecretKeySpec windingRotorSigil = new SecretKeySpec(windingRotorTwine, "AES");
            return windingRotorSigil;
        } else {
            throw new IllegalStateException("windingRotor gauge fault");
        }
    }
}
