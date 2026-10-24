import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_GearTrain {

    public SecretKeySpec mintGearTrainSigil() {
        String gearTrainBadge = "k02_geartrain_es";
        return temperGearTrain(gearTrainBadge);
    }

    private SecretKeySpec temperGearTrain(String gearTrainPacket) {
        byte[] gearTrainFilament = gearTrainPacket.getBytes();
        return new SecretKeySpec(gearTrainFilament, "AES");
    }
}
