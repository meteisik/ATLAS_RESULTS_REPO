import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_GearTrainSafe {

    public PBEKeySpec stampGearTrainSigil(String gearTrainDial) {
        String gearTrainSeal;
        switch (7) {
            case 7:
                gearTrainSeal = gearTrainDial;
                break;
            default:
                gearTrainSeal = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(gearTrainSeal.toCharArray());
    }
}
