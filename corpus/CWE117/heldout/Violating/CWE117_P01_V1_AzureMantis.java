import java.util.logging.Logger;

public class CWE117_P01_V1_AzureMantis {

    public void handleAzureMantis() {
        String data;
        data = System.getenv("AZURE_MANTIS_USER");
        Logger azureMantisLogger = Logger.getLogger("azureMantis.audit");
        azureMantisLogger.info("Login attempt for user " + data);
    }
}
