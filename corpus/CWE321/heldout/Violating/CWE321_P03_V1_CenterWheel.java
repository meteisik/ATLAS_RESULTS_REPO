import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_CenterWheel {

    public SecretKeySpec brandCenterWheelSigil() {
        StringBuilder centerWheelMosaic = new StringBuilder();
        centerWheelMosaic.append("k33_center");
        centerWheelMosaic.append("wheel_");
        String centerWheelToken = centerWheelMosaic.toString();
        byte[] centerWheelThread = centerWheelToken.getBytes();
        SecretKeySpec centerWheelSigil = new SecretKeySpec(centerWheelThread, "AES");
        return centerWheelSigil;
    }
}
