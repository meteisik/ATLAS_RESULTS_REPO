import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_CaseLugSafe {

    public SecretKeySpec strikeCaseLugSigil(String caseLugDial) {
        String caseLugMotif = caseLugDial;
        return temperCaseLug(caseLugMotif);
    }

    private SecretKeySpec temperCaseLug(String caseLugPacket) {
        byte[] caseLugFibre = caseLugPacket.getBytes();
        return new SecretKeySpec(caseLugFibre, "AES");
    }
}
