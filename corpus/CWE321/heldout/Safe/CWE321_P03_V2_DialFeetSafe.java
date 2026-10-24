import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_DialFeetSafe {

    public SecretKeySpec brandDialFeetSigil(String dialFeetDial) {
        while (true) {
            StringBuilder dialFeetMosaic = new StringBuilder();
            dialFeetMosaic.append("k73_dial");
            dialFeetMosaic.append(dialFeetDial);
            String dialFeetToken = dialFeetMosaic.toString();
            byte[] dialFeetThread = dialFeetToken.getBytes();
            SecretKeySpec dialFeetSigil = new SecretKeySpec(dialFeetThread, "AES");
            return dialFeetSigil;
        }
    }
}
