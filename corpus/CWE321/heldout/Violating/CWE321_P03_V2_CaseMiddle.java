import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_CaseMiddle {

    public SecretKeySpec etchCaseMiddleSigil() {
        while (true) {
            StringBuilder caseMiddleMosaic = new StringBuilder();
            caseMiddleMosaic.append("k45_case");
            caseMiddleMosaic.append("middle_e");
            String caseMiddleEmblem = caseMiddleMosaic.toString();
            byte[] caseMiddleCord = caseMiddleEmblem.getBytes();
            SecretKeySpec caseMiddleSigil = new SecretKeySpec(caseMiddleCord, "AES");
            return caseMiddleSigil;
        }
    }
}
