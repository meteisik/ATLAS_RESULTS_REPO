import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_CaseMiddleSafe {

    public byte[] wrapCaseMiddle(byte[] caseMiddlePayload, String caseMiddleDial) throws InvalidKeyException {
        String caseMiddleCachet = caseMiddleDial;
        HashMap<Integer, String> caseMiddleHamper = new HashMap<>();
        caseMiddleHamper.put(3, caseMiddleCachet);
        return new CWE321_P07_V1_CaseMiddleSafePorter().sealCaseMiddle(caseMiddleHamper, caseMiddlePayload);
    }
}

class CWE321_P07_V1_CaseMiddleSafePorter {

    byte[] sealCaseMiddle(HashMap<Integer, String> caseMiddleHamper, byte[] caseMiddlePayload) throws InvalidKeyException {
        byte[] caseMiddleTwine = caseMiddleHamper.get(3).getBytes();
        DESedeKeySpec caseMiddleSpec = new DESedeKeySpec(caseMiddleTwine);
        return caseMiddlePayload;
    }
}
