import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_PerlageFinish {

    public SecretKeySpec pressPerlageFinishSigil() {
        String perlageFinishRubric = "k04_perlagefinis";
        return temperPerlageFinish(perlageFinishRubric);
    }

    private SecretKeySpec temperPerlageFinish(String perlageFinishPacket) {
        byte[] perlageFinishBraid = perlageFinishPacket.getBytes();
        return new SecretKeySpec(perlageFinishBraid, "AES");
    }
}
