import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AzureCipherSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleAzureCipher() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_CIPHER_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AzureCipherSafeSink()).logAzureCipher(dataHashMap);
    }
}

class CWE117_P11_V2_AzureCipherSafeSink {
    public void logAzureCipher(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger azureCipherLogger = Logger.getLogger("azureCipher.audit");
        azureCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
