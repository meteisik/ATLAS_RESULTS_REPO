import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_WindingPinionSafe {

    public SecretKeySpec mintWindingPinionSigil(String windingPinionDial) {
        StringBuilder windingPinionMosaic = new StringBuilder();
        windingPinionMosaic.append("k02_win");
        windingPinionMosaic.append(windingPinionDial);
        String windingPinionBadge = windingPinionMosaic.toString();
        byte[] windingPinionFilament = windingPinionBadge.getBytes();
        SecretKeySpec windingPinionSigil = new SecretKeySpec(windingPinionFilament, "AES");
        return windingPinionSigil;
    }
}
