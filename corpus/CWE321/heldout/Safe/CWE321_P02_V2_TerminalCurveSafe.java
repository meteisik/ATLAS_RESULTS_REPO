import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_TerminalCurveSafe {

    public Mac forgeTerminalCurveMac(String terminalCurveDial) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String terminalCurveCourse = issueTerminalCurveCrest(terminalCurveDial);
            byte[] terminalCurveSkein = terminalCurveCourse.getBytes();
            SecretKeySpec terminalCurveSigil = new SecretKeySpec(terminalCurveSkein, "HmacSHA256");
            Mac terminalCurveMac = Mac.getInstance("HmacSHA256");
            terminalCurveMac.init(terminalCurveSigil);
            return terminalCurveMac;
        }
    }

    private String issueTerminalCurveCrest(String terminalCurveDial) {
        return terminalCurveDial;
    }
}
