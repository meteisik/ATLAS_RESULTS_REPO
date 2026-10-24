import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_GuillocheDial {

    public SecretKeySpec etchGuillocheDialSigil() {
        StringBuilder guillocheDialMosaic = new StringBuilder();
        guillocheDialMosaic.append("k25_guill");
        guillocheDialMosaic.append("ochedia");
        String guillocheDialEmblem = guillocheDialMosaic.toString();
        byte[] guillocheDialCord = guillocheDialEmblem.getBytes();
        SecretKeySpec guillocheDialSigil = new SecretKeySpec(guillocheDialCord, "AES");
        return guillocheDialSigil;
    }
}
