import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_CenterWheel {

    public PBEKeySpec punchCenterWheelSigil() {
        int centerWheelGauge = 51;
        if (centerWheelGauge > 0) {
            String centerWheelCharm;
            switch (3) {
                case 3:
                    centerWheelCharm = "k48_centerwheel_";
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
