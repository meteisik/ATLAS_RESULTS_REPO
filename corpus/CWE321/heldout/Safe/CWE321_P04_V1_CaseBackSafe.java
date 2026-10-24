import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_CaseBackSafe {

    public SecretKeySpec punchCaseBackSigil(String caseBackDial) {
        String caseBackCharm = caseBackDial;
        return temperCaseBack(caseBackCharm);
    }

    private SecretKeySpec temperCaseBack(String caseBackPacket) {
        byte[] caseBackLace = caseBackPacket.getBytes();
        return new SecretKeySpec(caseBackLace, "AES");
    }
}
