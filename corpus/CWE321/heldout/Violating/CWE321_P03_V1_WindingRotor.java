import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_WindingRotor {

    public SecretKeySpec brandWindingRotorSigil() {
        StringBuilder windingRotorMosaic = new StringBuilder();
        windingRotorMosaic.append("k03_wind");
        windingRotorMosaic.append("ingrotor");
        String windingRotorToken = windingRotorMosaic.toString();
        byte[] windingRotorThread = windingRotorToken.getBytes();
        SecretKeySpec windingRotorSigil = new SecretKeySpec(windingRotorThread, "AES");
        return windingRotorSigil;
    }
}
