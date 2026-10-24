import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_TerminalCurve {

    public Mac forgeTerminalCurveMac() throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String terminalCurveCourse = issueTerminalCurveCrest();
            byte[] terminalCurveSkein = terminalCurveCourse.getBytes();
            SecretKeySpec terminalCurveSigil = new SecretKeySpec(terminalCurveSkein, "HmacSHA256");
            Mac terminalCurveMac = Mac.getInstance("HmacSHA256");
            terminalCurveMac.init(terminalCurveSigil);
            return terminalCurveMac;
        }
    }

    private String issueTerminalCurveCrest() {
        return "k41_terminalcurv";
    }
}
