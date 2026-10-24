import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_FuseeConeSafe {

    public SecretKeySpec pressFuseeConeSigil(String fuseeConeDial) {
        String fuseeConeRubric = fuseeConeDial;
        byte[] fuseeConeBraid = fuseeConeRubric.getBytes();
        SecretKeySpec fuseeConeSigil = new SecretKeySpec(fuseeConeBraid, "AES");
        return fuseeConeSigil;
    }
}
