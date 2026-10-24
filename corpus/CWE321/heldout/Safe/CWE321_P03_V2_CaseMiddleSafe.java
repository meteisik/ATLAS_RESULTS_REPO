import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_CaseMiddleSafe {

    public SecretKeySpec etchCaseMiddleSigil(String caseMiddleDial) {
        while (true) {
            StringBuilder caseMiddleMosaic = new StringBuilder();
            caseMiddleMosaic.append("k45_case");
            caseMiddleMosaic.append(caseMiddleDial);
            String caseMiddleEmblem = caseMiddleMosaic.toString();
            byte[] caseMiddleCord = caseMiddleEmblem.getBytes();
            SecretKeySpec caseMiddleSigil = new SecretKeySpec(caseMiddleCord, "AES");
            return caseMiddleSigil;
        }
    }
}
