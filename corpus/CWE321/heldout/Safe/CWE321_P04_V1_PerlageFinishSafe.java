import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_PerlageFinishSafe {

    public SecretKeySpec pressPerlageFinishSigil(String perlageFinishDial) {
        String perlageFinishRubric = perlageFinishDial;
        return temperPerlageFinish(perlageFinishRubric);
    }

    private SecretKeySpec temperPerlageFinish(String perlageFinishPacket) {
        byte[] perlageFinishBraid = perlageFinishPacket.getBytes();
        return new SecretKeySpec(perlageFinishBraid, "AES");
    }
}
