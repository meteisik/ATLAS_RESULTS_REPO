import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_StrikeTrainSafe {

    public SecretKeySpec strikeStrikeTrainSigil(String strikeTrainDial) {
        String strikeTrainMotif = strikeTrainDial;
        byte[] strikeTrainFibre = strikeTrainMotif.getBytes();
        SecretKeySpec strikeTrainSigil = new SecretKeySpec(strikeTrainFibre, "AES");
        return strikeTrainSigil;
    }
}
