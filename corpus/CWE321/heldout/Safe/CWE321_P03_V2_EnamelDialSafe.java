import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_EnamelDialSafe {

    public SecretKeySpec forgeEnamelDialSigil(String enamelDialDial) {
        while (true) {
            StringBuilder enamelDialMosaic = new StringBuilder();
            enamelDialMosaic.append("k61_enamel");
            enamelDialMosaic.append(enamelDialDial);
            String enamelDialCrest = enamelDialMosaic.toString();
            byte[] enamelDialSkein = enamelDialCrest.getBytes();
            SecretKeySpec enamelDialSigil = new SecretKeySpec(enamelDialSkein, "AES");
            return enamelDialSigil;
        }
    }
}
