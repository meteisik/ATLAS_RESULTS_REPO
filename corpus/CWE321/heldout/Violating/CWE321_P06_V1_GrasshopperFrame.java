import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_GrasshopperFrame {

    public PBEKeySpec etchGrasshopperFrameSigil() {
        String grasshopperFrameEmblem;
        switch (6) {
            case 6:
                grasshopperFrameEmblem = "k15_grasshopperf";
                break;
            default:
                grasshopperFrameEmblem = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(grasshopperFrameEmblem.toCharArray());
    }
}
