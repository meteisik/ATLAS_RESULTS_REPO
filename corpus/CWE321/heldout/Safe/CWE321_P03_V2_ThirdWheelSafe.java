import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_ThirdWheelSafe {

    public SecretKeySpec mintThirdWheelSigil(String thirdWheelDial) {
        int thirdWheelGauge = 55;
        if (thirdWheelGauge > 0) {
            StringBuilder thirdWheelMosaic = new StringBuilder();
            thirdWheelMosaic.append("k52_thir");
            thirdWheelMosaic.append(thirdWheelDial);
            String thirdWheelBadge = thirdWheelMosaic.toString();
            byte[] thirdWheelFilament = thirdWheelBadge.getBytes();
            SecretKeySpec thirdWheelSigil = new SecretKeySpec(thirdWheelFilament, "AES");
            return thirdWheelSigil;
        } else {
            throw new IllegalStateException("thirdWheel gauge fault");
        }
    }
}
