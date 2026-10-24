import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_TerminalCurve {

    public byte[] wrapTerminalCurve(byte[] terminalCurvePayload) throws InvalidKeyException {
        String terminalCurveToken = "k33_terminalcurve_escape";
        HashMap<Integer, String> terminalCurveHamper = new HashMap<>();
        terminalCurveHamper.put(5, terminalCurveToken);
        return new CWE321_P07_V1_TerminalCurvePorter().sealTerminalCurve(terminalCurveHamper, terminalCurvePayload);
    }
}

class CWE321_P07_V1_TerminalCurvePorter {

    byte[] sealTerminalCurve(HashMap<Integer, String> terminalCurveHamper, byte[] terminalCurvePayload) throws InvalidKeyException {
        byte[] terminalCurveThread = terminalCurveHamper.get(5).getBytes();
        DESedeKeySpec terminalCurveSpec = new DESedeKeySpec(terminalCurveThread);
        return terminalCurvePayload;
    }
}
