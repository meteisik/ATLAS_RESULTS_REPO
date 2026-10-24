import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_CaseBack {

    public SecretKeySpec punchCaseBackSigil() {
        String caseBackCharm = "k08_caseback_esc";
        return temperCaseBack(caseBackCharm);
    }

    private SecretKeySpec temperCaseBack(String caseBackPacket) {
        byte[] caseBackLace = caseBackPacket.getBytes();
        return new SecretKeySpec(caseBackLace, "AES");
    }
}
