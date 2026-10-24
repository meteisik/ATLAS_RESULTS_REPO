import java.util.logging.Logger;

public class CWE117_P01_V1_AzureCascade {

    public void handleAzureCascade() {
        String data;
        data = System.getenv("AZURE_CASCADE_USER");
        Logger azureCascadeLogger = Logger.getLogger("azureCascade.audit");
        azureCascadeLogger.info("Login attempt for user " + data);
    }
}
