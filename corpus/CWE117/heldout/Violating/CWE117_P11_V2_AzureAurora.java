import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AzureAurora {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleAzureAurora() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AZURE_AURORA_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AzureAuroraSink()).logAzureAurora(dataHashMap);
    }
}

class CWE117_P11_V2_AzureAuroraSink {
    public void logAzureAurora(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger azureAuroraLogger = Logger.getLogger("azureAurora.audit");
        azureAuroraLogger.info("Login attempt for user " + data);
    }
}
