import java.util.logging.Logger;

public class CWE117_P01_V1_AzureMantisSafe {

    public void handleAzureMantis() {
        String data;
        data = System.getenv("AZURE_MANTIS_USER");
        Logger azureMantisLogger = Logger.getLogger("azureMantis.audit");
        azureMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
