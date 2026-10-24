import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_DialTrainSafe {

    public SecretKeySpec castDialTrainSigil(String dialTrainDial) {
        String dialTrainCachet = dialTrainDial;
        return temperDialTrain(dialTrainCachet);
    }

    private SecretKeySpec temperDialTrain(String dialTrainPacket) {
        byte[] dialTrainTwine = dialTrainPacket.getBytes();
        return new SecretKeySpec(dialTrainTwine, "AES");
    }
}
