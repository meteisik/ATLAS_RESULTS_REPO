import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_CaseMiddleSafe {

    public SecretKeySpec mintCaseMiddleSigil(String caseMiddleDial) {
        for (int caseMiddleLap = 0; caseMiddleLap < 1; caseMiddleLap++) {
            String caseMiddleBadge = caseMiddleDial;
            return temperCaseMiddle(caseMiddleBadge);
        }
        throw new IllegalStateException("caseMiddle lap fault");
    }

    private SecretKeySpec temperCaseMiddle(String caseMiddlePacket) {
        byte[] caseMiddleFilament = caseMiddlePacket.getBytes();
        return new SecretKeySpec(caseMiddleFilament, "AES");
    }
}
