import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_TerminalCurveSafe {

    public byte[] wrapTerminalCurve(byte[] terminalCurvePayload, String terminalCurveDial) throws InvalidKeyException {
        String terminalCurveToken = terminalCurveDial;
        HashMap<Integer, String> terminalCurveHamper = new HashMap<>();
        terminalCurveHamper.put(5, terminalCurveToken);
        return new CWE321_P07_V1_TerminalCurveSafePorter().sealTerminalCurve(terminalCurveHamper, terminalCurvePayload);
    }
}

class CWE321_P07_V1_TerminalCurveSafePorter {

    byte[] sealTerminalCurve(HashMap<Integer, String> terminalCurveHamper, byte[] terminalCurvePayload) throws InvalidKeyException {
        byte[] terminalCurveThread = terminalCurveHamper.get(5).getBytes();
        DESedeKeySpec terminalCurveSpec = new DESedeKeySpec(terminalCurveThread);
        return terminalCurvePayload;
    }
}
