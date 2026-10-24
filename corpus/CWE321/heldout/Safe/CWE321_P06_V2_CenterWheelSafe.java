import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_CenterWheelSafe {

    public PBEKeySpec punchCenterWheelSigil(String centerWheelDial) {
        int centerWheelGauge = 51;
        if (centerWheelGauge > 0) {
            String centerWheelCharm;
            switch (3) {
                case 3:
                    centerWheelCharm = centerWheelDial;
                    break;
                default:
                    centerWheelCharm = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(centerWheelCharm.toCharArray());
        } else {
            throw new IllegalStateException("centerWheel gauge fault");
        }
    }
}
