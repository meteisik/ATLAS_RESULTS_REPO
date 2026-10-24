import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_GearTrainSafe {

    public SecretKeySpec mintGearTrainSigil(String gearTrainDial) {
        String gearTrainBadge = gearTrainDial;
        return temperGearTrain(gearTrainBadge);
    }

    private SecretKeySpec temperGearTrain(String gearTrainPacket) {
        byte[] gearTrainFilament = gearTrainPacket.getBytes();
        return new SecretKeySpec(gearTrainFilament, "AES");
    }
}
