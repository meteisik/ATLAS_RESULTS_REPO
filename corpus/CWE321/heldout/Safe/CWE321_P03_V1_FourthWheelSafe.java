import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_FourthWheelSafe {

    public SecretKeySpec punchFourthWheelSigil(String fourthWheelDial) {
        StringBuilder fourthWheelMosaic = new StringBuilder();
        fourthWheelMosaic.append("k18_fourt");
        fourthWheelMosaic.append(fourthWheelDial);
        String fourthWheelCharm = fourthWheelMosaic.toString();
        byte[] fourthWheelLace = fourthWheelCharm.getBytes();
        SecretKeySpec fourthWheelSigil = new SecretKeySpec(fourthWheelLace, "AES");
        return fourthWheelSigil;
    }
}
