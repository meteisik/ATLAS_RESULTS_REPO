import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SolarCipherSafe {

    public void handleSolarCipher() {
        String data;
        data = System.getenv("SOLAR_CIPHER_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SolarCipherSafeSink()).logSolarCipher(dataHashMap);
    }
}

class CWE117_P11_V1_SolarCipherSafeSink {
    public void logSolarCipher(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger solarCipherLogger = Logger.getLogger("solarCipher.audit");
        solarCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
