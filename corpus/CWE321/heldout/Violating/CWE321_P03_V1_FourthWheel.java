import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_FourthWheel {

    public SecretKeySpec punchFourthWheelSigil() {
        StringBuilder fourthWheelMosaic = new StringBuilder();
        fourthWheelMosaic.append("k18_fourt");
        fourthWheelMosaic.append("hwheel_");
        String fourthWheelCharm = fourthWheelMosaic.toString();
        byte[] fourthWheelLace = fourthWheelCharm.getBytes();
        SecretKeySpec fourthWheelSigil = new SecretKeySpec(fourthWheelLace, "AES");
        return fourthWheelSigil;
    }
}
