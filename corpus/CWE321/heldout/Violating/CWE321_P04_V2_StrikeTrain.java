import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_StrikeTrain {

    public SecretKeySpec etchStrikeTrainSigil() {
        while (true) {
            String strikeTrainEmblem = "k45_striketrain_";
            return temperStrikeTrain(strikeTrainEmblem);
        }
    }

    private SecretKeySpec temperStrikeTrain(String strikeTrainPacket) {
        byte[] strikeTrainCord = strikeTrainPacket.getBytes();
        return new SecretKeySpec(strikeTrainCord, "AES");
    }
}
