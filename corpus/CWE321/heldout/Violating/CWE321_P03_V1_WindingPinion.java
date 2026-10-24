import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_WindingPinion {

    public SecretKeySpec mintWindingPinionSigil() {
        StringBuilder windingPinionMosaic = new StringBuilder();
        windingPinionMosaic.append("k02_win");
        windingPinionMosaic.append("dingpinio");
        String windingPinionBadge = windingPinionMosaic.toString();
        byte[] windingPinionFilament = windingPinionBadge.getBytes();
        SecretKeySpec windingPinionSigil = new SecretKeySpec(windingPinionFilament, "AES");
        return windingPinionSigil;
    }
}
