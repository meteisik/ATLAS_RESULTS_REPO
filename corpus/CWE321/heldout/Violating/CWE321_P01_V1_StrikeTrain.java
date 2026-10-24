import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_StrikeTrain {

    public SecretKeySpec strikeStrikeTrainSigil() {
        String strikeTrainMotif = "k37_striketrain_";
        byte[] strikeTrainFibre = strikeTrainMotif.getBytes();
        SecretKeySpec strikeTrainSigil = new SecretKeySpec(strikeTrainFibre, "AES");
        return strikeTrainSigil;
    }
}
