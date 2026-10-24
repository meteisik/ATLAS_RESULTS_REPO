import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_RetrogradeHandSafe {

    public SecretKeySpec stampRetrogradeHandSigil(String retrogradeHandDial) {
        int retrogradeHandGauge = 63;
        if (retrogradeHandGauge > 0) {
            String retrogradeHandSeal = retrogradeHandDial;
            return temperRetrogradeHand(retrogradeHandSeal);
        } else {
            throw new IllegalStateException("retrogradeHand gauge fault");
        }
    }

    private SecretKeySpec temperRetrogradeHand(String retrogradeHandPacket) {
        byte[] retrogradeHandStrand = retrogradeHandPacket.getBytes();
        return new SecretKeySpec(retrogradeHandStrand, "AES");
    }
}
