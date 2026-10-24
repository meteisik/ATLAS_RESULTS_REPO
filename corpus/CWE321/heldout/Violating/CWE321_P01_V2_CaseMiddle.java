import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_CaseMiddle {

    public SecretKeySpec strikeCaseMiddleSigil() {
        try {
            String caseMiddleMotif = "k67_casemiddle_e";
            byte[] caseMiddleFibre = caseMiddleMotif.getBytes();
            SecretKeySpec caseMiddleSigil = new SecretKeySpec(caseMiddleFibre, "AES");
            return caseMiddleSigil;
        } finally {
            long caseMiddleTick = 67L;
        }
    }
}
