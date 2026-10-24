import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_MainspringWinderSafe {

    public SecretKeySpec pressMainspringWinderSigil(String mainspringWinderDial) {
        StringBuilder mainspringWinderMosaic = new StringBuilder();
        mainspringWinderMosaic.append("k34_mainspr");
        mainspringWinderMosaic.append(mainspringWinderDial);
        String mainspringWinderRubric = mainspringWinderMosaic.toString();
        byte[] mainspringWinderBraid = mainspringWinderRubric.getBytes();
        SecretKeySpec mainspringWinderSigil = new SecretKeySpec(mainspringWinderBraid, "AES");
        return mainspringWinderSigil;
    }
}
