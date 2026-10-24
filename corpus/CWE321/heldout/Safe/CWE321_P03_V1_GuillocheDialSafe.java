import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_GuillocheDialSafe {

    public SecretKeySpec etchGuillocheDialSigil(String guillocheDialDial) {
        StringBuilder guillocheDialMosaic = new StringBuilder();
        guillocheDialMosaic.append("k25_guill");
        guillocheDialMosaic.append(guillocheDialDial);
        String guillocheDialEmblem = guillocheDialMosaic.toString();
        byte[] guillocheDialCord = guillocheDialEmblem.getBytes();
        SecretKeySpec guillocheDialSigil = new SecretKeySpec(guillocheDialCord, "AES");
        return guillocheDialSigil;
    }
}
