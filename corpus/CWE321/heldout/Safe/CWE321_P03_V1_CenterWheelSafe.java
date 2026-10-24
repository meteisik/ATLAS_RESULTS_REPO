import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_CenterWheelSafe {

    public SecretKeySpec brandCenterWheelSigil(String centerWheelDial) {
        StringBuilder centerWheelMosaic = new StringBuilder();
        centerWheelMosaic.append("k33_center");
        centerWheelMosaic.append(centerWheelDial);
        String centerWheelToken = centerWheelMosaic.toString();
        byte[] centerWheelThread = centerWheelToken.getBytes();
        SecretKeySpec centerWheelSigil = new SecretKeySpec(centerWheelThread, "AES");
        return centerWheelSigil;
    }
}
