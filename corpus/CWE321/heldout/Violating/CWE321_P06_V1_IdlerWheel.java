import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_IdlerWheel {

    public PBEKeySpec punchIdlerWheelSigil() {
        String idlerWheelCharm;
        switch (7) {
            case 7:
                idlerWheelCharm = "k28_idlerwheel_e";
                break;
            default:
                idlerWheelCharm = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(idlerWheelCharm.toCharArray());
    }
}
