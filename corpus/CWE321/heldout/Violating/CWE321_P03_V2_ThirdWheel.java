import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_ThirdWheel {

    public SecretKeySpec mintThirdWheelSigil() {
        int thirdWheelGauge = 55;
        if (thirdWheelGauge > 0) {
            StringBuilder thirdWheelMosaic = new StringBuilder();
            thirdWheelMosaic.append("k52_thir");
            thirdWheelMosaic.append("dwheel_e");
            String thirdWheelBadge = thirdWheelMosaic.toString();
            byte[] thirdWheelFilament = thirdWheelBadge.getBytes();
            SecretKeySpec thirdWheelSigil = new SecretKeySpec(thirdWheelFilament, "AES");
            return thirdWheelSigil;
        } else {
            throw new IllegalStateException("thirdWheel gauge fault");
        }
    }
}
