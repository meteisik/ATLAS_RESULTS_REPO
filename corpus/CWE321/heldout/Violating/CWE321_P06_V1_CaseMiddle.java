import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_CaseMiddle {

    public PBEKeySpec brandCaseMiddleSigil() {
        String caseMiddleToken;
        switch (6) {
            case 6:
                caseMiddleToken = "k03_casemiddle_e";
                break;
            default:
                caseMiddleToken = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(caseMiddleToken.toCharArray());
    }
}
