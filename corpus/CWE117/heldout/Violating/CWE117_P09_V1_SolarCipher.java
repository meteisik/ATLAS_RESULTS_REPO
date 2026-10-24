import java.util.logging.Logger;

public class CWE117_P09_V1_SolarCipher {

    static class Container {
        public String containerOne;
    }

    public void handleSolarCipher() {
        String data;
        data = System.getenv("SOLAR_CIPHER_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SolarCipherSink()).logSolarCipher(dataContainer);
    }
}

class CWE117_P09_V1_SolarCipherSink {
    public void logSolarCipher(CWE117_P09_V1_SolarCipher.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger solarCipherLogger = Logger.getLogger("solarCipher.audit");
        solarCipherLogger.info("Login attempt for user " + data);
    }
}
