import java.util.logging.Logger;

public class CWE117_P09_V2_AmberCipherSafe {

    static class Container {
        public String containerOne;
    }

    public void handleAmberCipher() {
        String data;
        while (true) {
            data = System.getenv("AMBER_CIPHER_USER");
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_AmberCipherSafeSink()).logAmberCipher(dataContainer);
    }
}

class CWE117_P09_V2_AmberCipherSafeSink {
    public void logAmberCipher(CWE117_P09_V2_AmberCipherSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger amberCipherLogger = Logger.getLogger("amberCipher.audit");
        amberCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
