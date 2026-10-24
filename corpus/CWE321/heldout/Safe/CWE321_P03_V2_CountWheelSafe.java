import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_CountWheelSafe {

    public SecretKeySpec stampCountWheelSigil(String countWheelDial) {
        int countWheelGauge = 63;
        if (countWheelGauge > 0) {
            StringBuilder countWheelMosaic = new StringBuilder();
            countWheelMosaic.append("k60_count");
            countWheelMosaic.append(countWheelDial);
            String countWheelSeal = countWheelMosaic.toString();
            byte[] countWheelStrand = countWheelSeal.getBytes();
            SecretKeySpec countWheelSigil = new SecretKeySpec(countWheelStrand, "AES");
            return countWheelSigil;
        } else {
            throw new IllegalStateException("countWheel gauge fault");
        }
    }
}
