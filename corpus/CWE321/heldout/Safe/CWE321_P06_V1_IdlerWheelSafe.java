import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_IdlerWheelSafe {

    public PBEKeySpec punchIdlerWheelSigil(String idlerWheelDial) {
        String idlerWheelCharm;
        switch (7) {
            case 7:
                idlerWheelCharm = idlerWheelDial;
                break;
            default:
                idlerWheelCharm = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(idlerWheelCharm.toCharArray());
    }
}
