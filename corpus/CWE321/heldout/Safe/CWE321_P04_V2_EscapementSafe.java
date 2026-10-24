import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_EscapementSafe {

    public SecretKeySpec pressEscapementSigil(String escapementDial) {
        int escapementGauge = 67;
        if (escapementGauge > 0) {
            String escapementRubric = escapementDial;
            return temperEscapement(escapementRubric);
        } else {
            throw new IllegalStateException("escapement gauge fault");
        }
    }

    private SecretKeySpec temperEscapement(String escapementPacket) {
        byte[] escapementBraid = escapementPacket.getBytes();
        return new SecretKeySpec(escapementBraid, "AES");
    }
}
