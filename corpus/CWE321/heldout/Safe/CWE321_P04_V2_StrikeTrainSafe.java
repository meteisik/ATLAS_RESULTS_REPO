import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_StrikeTrainSafe {

    public SecretKeySpec etchStrikeTrainSigil(String strikeTrainDial) {
        while (true) {
            String strikeTrainEmblem = strikeTrainDial;
            return temperStrikeTrain(strikeTrainEmblem);
        }
    }

    private SecretKeySpec temperStrikeTrain(String strikeTrainPacket) {
        byte[] strikeTrainCord = strikeTrainPacket.getBytes();
        return new SecretKeySpec(strikeTrainCord, "AES");
    }
}
