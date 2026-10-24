import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrCipher {
    private static boolean privateTrue = true;

    static class Container {
        public String containerOne;
    }

    public void handleZephyrCipher() {
        String data;
        if (privateTrue) {
            data = System.getenv("ZEPHYR_CIPHER_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_ZephyrCipherSink()).logZephyrCipher(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrCipherSink {
    public void logZephyrCipher(CWE117_P09_V2_ZephyrCipher.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrCipherLogger = Logger.getLogger("zephyrCipher.audit");
        zephyrCipherLogger.info("Login attempt for user " + data);
    }
}
