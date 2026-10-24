import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_BarrelArborSafe {

    public SecretKeySpec mintBarrelArborSigil(String barrelArborDial) {
        StringBuilder barrelArborMosaic = new StringBuilder();
        barrelArborMosaic.append("k22_ba");
        barrelArborMosaic.append(barrelArborDial);
        String barrelArborBadge = barrelArborMosaic.toString();
        byte[] barrelArborFilament = barrelArborBadge.getBytes();
        SecretKeySpec barrelArborSigil = new SecretKeySpec(barrelArborFilament, "AES");
        return barrelArborSigil;
    }
}
