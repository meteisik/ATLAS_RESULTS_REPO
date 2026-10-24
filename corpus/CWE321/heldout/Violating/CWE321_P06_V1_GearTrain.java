import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_GearTrain {

    public PBEKeySpec stampGearTrainSigil() {
        String gearTrainSeal;
        switch (7) {
            case 7:
                gearTrainSeal = "k10_geartrain_es";
                break;
            default:
                gearTrainSeal = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(gearTrainSeal.toCharArray());
    }
}
