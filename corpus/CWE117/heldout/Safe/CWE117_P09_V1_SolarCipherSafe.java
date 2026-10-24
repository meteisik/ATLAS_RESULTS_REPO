import java.util.logging.Logger;

public class CWE117_P09_V1_SolarCipherSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSolarCipher() {
        String data;
        data = System.getenv("SOLAR_CIPHER_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SolarCipherSafeSink()).logSolarCipher(dataContainer);
    }
}

class CWE117_P09_V1_SolarCipherSafeSink {
    public void logSolarCipher(CWE117_P09_V1_SolarCipherSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger solarCipherLogger = Logger.getLogger("solarCipher.audit");
        solarCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
