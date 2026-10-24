import java.util.logging.Logger;

public class CWE117_P10_V1_SolarCipherSafe {

    public static String data;

    public void handleSolarCipher() {
        data = System.getenv("SOLAR_CIPHER_USER");
        (new CWE117_P10_V1_SolarCipherSafeSink()).logSolarCipher();
    }
}

class CWE117_P10_V1_SolarCipherSafeSink {
    public void logSolarCipher() {
        String data = CWE117_P10_V1_SolarCipherSafe.data;
        Logger solarCipherLogger = Logger.getLogger("solarCipher.audit");
        solarCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
