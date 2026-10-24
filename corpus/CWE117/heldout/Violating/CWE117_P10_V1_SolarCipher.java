import java.util.logging.Logger;

public class CWE117_P10_V1_SolarCipher {

    public static String data;

    public void handleSolarCipher() {
        data = System.getenv("SOLAR_CIPHER_USER");
        (new CWE117_P10_V1_SolarCipherSink()).logSolarCipher();
    }
}

class CWE117_P10_V1_SolarCipherSink {
    public void logSolarCipher() {
        String data = CWE117_P10_V1_SolarCipher.data;
        Logger solarCipherLogger = Logger.getLogger("solarCipher.audit");
        solarCipherLogger.info("Login attempt for user " + data);
    }
}
