import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrCipherSafe {

    public void handleZephyrCipher() {
        String data;
        if (5 == 5) {
            data = System.getenv("ZEPHYR_CIPHER_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_ZephyrCipherSafeSink()).logZephyrCipher(dataArray);
    }
}

class CWE117_P08_V2_ZephyrCipherSafeSink {
    public void logZephyrCipher(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrCipherLogger = Logger.getLogger("zephyrCipher.audit");
        zephyrCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
