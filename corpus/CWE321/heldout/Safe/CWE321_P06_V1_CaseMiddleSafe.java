import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_CaseMiddleSafe {

    public PBEKeySpec brandCaseMiddleSigil(String caseMiddleDial) {
        String caseMiddleToken;
        switch (6) {
            case 6:
                caseMiddleToken = caseMiddleDial;
                break;
            default:
                caseMiddleToken = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(caseMiddleToken.toCharArray());
    }
}
