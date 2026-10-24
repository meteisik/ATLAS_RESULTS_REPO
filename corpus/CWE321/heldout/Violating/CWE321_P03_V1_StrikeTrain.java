import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_StrikeTrain {

    public SecretKeySpec forgeStrikeTrainSigil() {
        StringBuilder strikeTrainMosaic = new StringBuilder();
        strikeTrainMosaic.append("k11_strik");
        strikeTrainMosaic.append("etrain_");
        String strikeTrainCrest = strikeTrainMosaic.toString();
        byte[] strikeTrainSkein = strikeTrainCrest.getBytes();
        SecretKeySpec strikeTrainSigil = new SecretKeySpec(strikeTrainSkein, "AES");
        return strikeTrainSigil;
    }
}
