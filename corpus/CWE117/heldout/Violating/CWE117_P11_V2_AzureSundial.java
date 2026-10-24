import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AzureSundial {

    public void handleAzureSundial() {
        String data;
        while (true) {
            data = System.getenv("AZURE_SUNDIAL_USER");
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AzureSundialSink()).logAzureSundial(dataHashMap);
    }
}

class CWE117_P11_V2_AzureSundialSink {
    public void logAzureSundial(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger azureSundialLogger = Logger.getLogger("azureSundial.audit");
        azureSundialLogger.info("Login attempt for user " + data);
    }
}
