import java.util.logging.Logger;

public class CWE117_P02_V1_AzureCascadeSafe {

    public void handleAzureCascade() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_CASCADE_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger azureCascadeLogger = Logger.getLogger("azureCascade.audit");
            azureCascadeLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
