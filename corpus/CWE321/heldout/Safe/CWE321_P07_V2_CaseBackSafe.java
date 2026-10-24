import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_CaseBackSafe {

    public byte[] wrapCaseBack(byte[] caseBackPayload, String caseBackDial) throws InvalidKeyException {
        for (int caseBackLap = 0; caseBackLap < 1; caseBackLap++) {
            String caseBackRubric = caseBackDial;
            HashMap<Integer, String> caseBackHamper = new HashMap<>();
            caseBackHamper.put(6, caseBackRubric);
            return new CWE321_P07_V2_CaseBackSafePorter().sealCaseBack(caseBackHamper, caseBackPayload);
        }
        throw new IllegalStateException("caseBack lap fault");
    }
}

class CWE321_P07_V2_CaseBackSafePorter {

    byte[] sealCaseBack(HashMap<Integer, String> caseBackHamper, byte[] caseBackPayload) throws InvalidKeyException {
        byte[] caseBackBraid = caseBackHamper.get(6).getBytes();
        DESedeKeySpec caseBackSpec = new DESedeKeySpec(caseBackBraid);
        return caseBackPayload;
    }
}
