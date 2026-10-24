import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_CannonPinionSafe {

    public SecretKeySpec stampCannonPinionSigil(String cannonPinionDial) {
        int cannonPinionGauge = 63;
        if (cannonPinionGauge > 0) {
            String cannonPinionSeal = cannonPinionDial;
            byte[] cannonPinionStrand = cannonPinionSeal.getBytes();
            SecretKeySpec cannonPinionSigil = new SecretKeySpec(cannonPinionStrand, "AES");
            return cannonPinionSigil;
        } else {
            throw new IllegalStateException("cannonPinion gauge fault");
        }
    }
}
