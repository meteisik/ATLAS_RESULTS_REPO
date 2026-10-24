import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_BezelSafe {

    public SecretKeySpec punchBezelSigil(String bezelDial) {
        StringBuilder bezelMosaic = new StringBuilder();
        bezelMosaic.append("k28_b");
        bezelMosaic.append(bezelDial);
        String bezelCharm = bezelMosaic.toString();
        byte[] bezelLace = bezelCharm.getBytes();
        SecretKeySpec bezelSigil = new SecretKeySpec(bezelLace, "AES");
        return bezelSigil;
    }
}
