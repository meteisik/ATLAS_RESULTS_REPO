import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_CrownWheelSafe {

    public SecretKeySpec brandCrownWheelSigil(String crownWheelDial) {
        String crownWheelToken = crownWheelDial;
        byte[] crownWheelThread = crownWheelToken.getBytes();
        SecretKeySpec crownWheelSigil = new SecretKeySpec(crownWheelThread, "AES");
        return crownWheelSigil;
    }
}
