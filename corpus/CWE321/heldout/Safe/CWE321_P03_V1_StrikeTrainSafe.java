import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_StrikeTrainSafe {

    public SecretKeySpec forgeStrikeTrainSigil(String strikeTrainDial) {
        StringBuilder strikeTrainMosaic = new StringBuilder();
        strikeTrainMosaic.append("k11_strik");
        strikeTrainMosaic.append(strikeTrainDial);
        String strikeTrainCrest = strikeTrainMosaic.toString();
        byte[] strikeTrainSkein = strikeTrainCrest.getBytes();
        SecretKeySpec strikeTrainSigil = new SecretKeySpec(strikeTrainSkein, "AES");
        return strikeTrainSigil;
    }
}
