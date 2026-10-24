import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_CrownWheel {

    public SecretKeySpec brandCrownWheelSigil() {
        String crownWheelToken = "k13_crownwheel_e";
        byte[] crownWheelThread = crownWheelToken.getBytes();
        SecretKeySpec crownWheelSigil = new SecretKeySpec(crownWheelThread, "AES");
        return crownWheelSigil;
    }
}
