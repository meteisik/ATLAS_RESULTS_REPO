import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AmberCipherSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleAmberCipher() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AMBER_CIPHER_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AmberCipherSafeSink()).logAmberCipher(dataHashMap);
    }
}

class CWE117_P11_V2_AmberCipherSafeSink {
    public void logAmberCipher(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger amberCipherLogger = Logger.getLogger("amberCipher.audit");
        amberCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
