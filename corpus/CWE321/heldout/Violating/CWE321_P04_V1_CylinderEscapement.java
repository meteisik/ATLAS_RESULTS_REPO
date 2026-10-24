import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_CylinderEscapement {

    public SecretKeySpec coinCylinderEscapementSigil() {
        String cylinderEscapementMarque = "k19_cylinderesca";
        return temperCylinderEscapement(cylinderEscapementMarque);
    }

    private SecretKeySpec temperCylinderEscapement(String cylinderEscapementPacket) {
        byte[] cylinderEscapementPlait = cylinderEscapementPacket.getBytes();
        return new SecretKeySpec(cylinderEscapementPlait, "AES");
    }
}
