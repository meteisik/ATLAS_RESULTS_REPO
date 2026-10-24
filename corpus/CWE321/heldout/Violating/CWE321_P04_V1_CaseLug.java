import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_CaseLug {

    public SecretKeySpec strikeCaseLugSigil() {
        String caseLugMotif = "k27_caselug_esca";
        return temperCaseLug(caseLugMotif);
    }

    private SecretKeySpec temperCaseLug(String caseLugPacket) {
        byte[] caseLugFibre = caseLugPacket.getBytes();
        return new SecretKeySpec(caseLugFibre, "AES");
    }
}
