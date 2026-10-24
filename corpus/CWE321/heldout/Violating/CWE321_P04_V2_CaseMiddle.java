import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_CaseMiddle {

    public SecretKeySpec mintCaseMiddleSigil() {
        for (int caseMiddleLap = 0; caseMiddleLap < 1; caseMiddleLap++) {
            String caseMiddleBadge = "k62_casemiddle_e";
            return temperCaseMiddle(caseMiddleBadge);
        }
        throw new IllegalStateException("caseMiddle lap fault");
    }

    private SecretKeySpec temperCaseMiddle(String caseMiddlePacket) {
        byte[] caseMiddleFilament = caseMiddlePacket.getBytes();
        return new SecretKeySpec(caseMiddleFilament, "AES");
    }
}
