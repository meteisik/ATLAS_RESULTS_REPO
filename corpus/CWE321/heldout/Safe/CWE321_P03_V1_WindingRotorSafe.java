import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_WindingRotorSafe {

    public SecretKeySpec brandWindingRotorSigil(String windingRotorDial) {
        StringBuilder windingRotorMosaic = new StringBuilder();
        windingRotorMosaic.append("k03_wind");
        windingRotorMosaic.append(windingRotorDial);
        String windingRotorToken = windingRotorMosaic.toString();
        byte[] windingRotorThread = windingRotorToken.getBytes();
        SecretKeySpec windingRotorSigil = new SecretKeySpec(windingRotorThread, "AES");
        return windingRotorSigil;
    }
}
