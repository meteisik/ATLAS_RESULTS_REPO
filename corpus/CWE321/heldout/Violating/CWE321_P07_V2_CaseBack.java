import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_CaseBack {

    public byte[] wrapCaseBack(byte[] caseBackPayload) throws InvalidKeyException {
        for (int caseBackLap = 0; caseBackLap < 1; caseBackLap++) {
            String caseBackRubric = "k74_caseback_escapewheel";
            HashMap<Integer, String> caseBackHamper = new HashMap<>();
            caseBackHamper.put(6, caseBackRubric);
            return new CWE321_P07_V2_CaseBackPorter().sealCaseBack(caseBackHamper, caseBackPayload);
        }
        throw new IllegalStateException("caseBack lap fault");
    }
}

class CWE321_P07_V2_CaseBackPorter {

    byte[] sealCaseBack(HashMap<Integer, String> caseBackHamper, byte[] caseBackPayload) throws InvalidKeyException {
        byte[] caseBackBraid = caseBackHamper.get(6).getBytes();
        DESedeKeySpec caseBackSpec = new DESedeKeySpec(caseBackBraid);
        return caseBackPayload;
    }
}
