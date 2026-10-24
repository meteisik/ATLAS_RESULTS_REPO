import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_DialTrain {

    public SecretKeySpec castDialTrainSigil() {
        String dialTrainCachet = "k36_dialtrain_es";
        return temperDialTrain(dialTrainCachet);
    }

    private SecretKeySpec temperDialTrain(String dialTrainPacket) {
        byte[] dialTrainTwine = dialTrainPacket.getBytes();
        return new SecretKeySpec(dialTrainTwine, "AES");
    }
}
