import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_ZephyrCipherSafe {

    public void handleZephyrCipher() {
        String data;
        data = System.getenv("ZEPHYR_CIPHER_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_ZephyrCipherSafeSink()).logZephyrCipher(dataHashMap);
    }
}

class CWE117_P11_V1_ZephyrCipherSafeSink {
    public void logZephyrCipher(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger zephyrCipherLogger = Logger.getLogger("zephyrCipher.audit");
        zephyrCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
