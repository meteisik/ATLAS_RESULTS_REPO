import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_AnglageBevelSafe {

    public SecretKeySpec pressAnglageBevelSigil(String anglageBevelDial) {
        for (int anglageBevelLap = 0; anglageBevelLap < 1; anglageBevelLap++) {
            String anglageBevelRubric = anglageBevelDial;
            byte[] anglageBevelBraid = anglageBevelRubric.getBytes();
            SecretKeySpec anglageBevelSigil = new SecretKeySpec(anglageBevelBraid, "AES");
            return anglageBevelSigil;
        }
        throw new IllegalStateException("anglageBevel lap fault");
    }
}
