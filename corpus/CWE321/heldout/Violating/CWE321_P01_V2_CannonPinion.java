import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_CannonPinion {

    public SecretKeySpec stampCannonPinionSigil() {
        int cannonPinionGauge = 63;
        if (cannonPinionGauge > 0) {
            String cannonPinionSeal = "k60_cannonpinion";
            byte[] cannonPinionStrand = cannonPinionSeal.getBytes();
            SecretKeySpec cannonPinionSigil = new SecretKeySpec(cannonPinionStrand, "AES");
            return cannonPinionSigil;
        } else {
            throw new IllegalStateException("cannonPinion gauge fault");
        }
    }
}
