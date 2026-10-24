import java.util.logging.Logger;

public class CWE117_P02_V1_AzureSundialSafe {

    public void handleAzureSundial() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_SUNDIAL_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger azureSundialLogger = Logger.getLogger("azureSundial.audit");
            azureSundialLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
