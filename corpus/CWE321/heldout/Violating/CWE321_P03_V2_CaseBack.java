import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_CaseBack {

    public SecretKeySpec punchCaseBackSigil() {
        int caseBackGauge = 71;
        if (caseBackGauge > 0) {
            StringBuilder caseBackMosaic = new StringBuilder();
            caseBackMosaic.append("k68_caseba");
            caseBackMosaic.append("ck_esc");
            String caseBackCharm = caseBackMosaic.toString();
            byte[] caseBackLace = caseBackCharm.getBytes();
            SecretKeySpec caseBackSigil = new SecretKeySpec(caseBackLace, "AES");
            return caseBackSigil;
        } else {
            throw new IllegalStateException("caseBack gauge fault");
        }
    }
}
