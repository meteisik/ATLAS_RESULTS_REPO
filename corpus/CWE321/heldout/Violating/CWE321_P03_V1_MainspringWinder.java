import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_MainspringWinder {

    public SecretKeySpec pressMainspringWinderSigil() {
        StringBuilder mainspringWinderMosaic = new StringBuilder();
        mainspringWinderMosaic.append("k34_mainspr");
        mainspringWinderMosaic.append("ingwi");
        String mainspringWinderRubric = mainspringWinderMosaic.toString();
        byte[] mainspringWinderBraid = mainspringWinderRubric.getBytes();
        SecretKeySpec mainspringWinderSigil = new SecretKeySpec(mainspringWinderBraid, "AES");
        return mainspringWinderSigil;
    }
}
