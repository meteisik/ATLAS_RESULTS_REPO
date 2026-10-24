import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_TerminalCurve {

    public SecretKeySpec punchTerminalCurveSigil() {
        StringBuilder terminalCurveMosaic = new StringBuilder();
        terminalCurveMosaic.append("k08_te");
        terminalCurveMosaic.append("rminalcurv");
        String terminalCurveCharm = terminalCurveMosaic.toString();
        byte[] terminalCurveLace = terminalCurveCharm.getBytes();
        SecretKeySpec terminalCurveSigil = new SecretKeySpec(terminalCurveLace, "AES");
        return terminalCurveSigil;
    }
}
