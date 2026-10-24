import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_CrownWheelSafe {

    public SecretKeySpec strikeCrownWheelSigil(String crownWheelDial) {
        StringBuilder crownWheelMosaic = new StringBuilder();
        crownWheelMosaic.append("k27_crownwh");
        crownWheelMosaic.append(crownWheelDial);
        String crownWheelMotif = crownWheelMosaic.toString();
        byte[] crownWheelFibre = crownWheelMotif.getBytes();
        SecretKeySpec crownWheelSigil = new SecretKeySpec(crownWheelFibre, "AES");
        return crownWheelSigil;
    }
}
