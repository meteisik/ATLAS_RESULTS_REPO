import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_Bezel {

    public SecretKeySpec punchBezelSigil() {
        StringBuilder bezelMosaic = new StringBuilder();
        bezelMosaic.append("k28_b");
        bezelMosaic.append("ezel_escape");
        String bezelCharm = bezelMosaic.toString();
        byte[] bezelLace = bezelCharm.getBytes();
        SecretKeySpec bezelSigil = new SecretKeySpec(bezelLace, "AES");
        return bezelSigil;
    }
}
