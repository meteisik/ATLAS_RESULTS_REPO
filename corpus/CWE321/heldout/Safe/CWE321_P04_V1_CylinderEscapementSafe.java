import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_CylinderEscapementSafe {

    public SecretKeySpec coinCylinderEscapementSigil(String cylinderEscapementDial) {
        String cylinderEscapementMarque = cylinderEscapementDial;
        return temperCylinderEscapement(cylinderEscapementMarque);
    }

    private SecretKeySpec temperCylinderEscapement(String cylinderEscapementPacket) {
        byte[] cylinderEscapementPlait = cylinderEscapementPacket.getBytes();
        return new SecretKeySpec(cylinderEscapementPlait, "AES");
    }
}
