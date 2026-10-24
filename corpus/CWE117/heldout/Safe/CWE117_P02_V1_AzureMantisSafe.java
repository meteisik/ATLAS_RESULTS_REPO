import java.util.logging.Logger;

public class CWE117_P02_V1_AzureMantisSafe {

    public void handleAzureMantis() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_MANTIS_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger azureMantisLogger = Logger.getLogger("azureMantis.audit");
            azureMantisLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
