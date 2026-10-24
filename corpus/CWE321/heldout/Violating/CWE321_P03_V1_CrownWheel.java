import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_CrownWheel {

    public SecretKeySpec strikeCrownWheelSigil() {
        StringBuilder crownWheelMosaic = new StringBuilder();
        crownWheelMosaic.append("k27_crownwh");
        crownWheelMosaic.append("eel_e");
        String crownWheelMotif = crownWheelMosaic.toString();
        byte[] crownWheelFibre = crownWheelMotif.getBytes();
        SecretKeySpec crownWheelSigil = new SecretKeySpec(crownWheelFibre, "AES");
        return crownWheelSigil;
    }
}
