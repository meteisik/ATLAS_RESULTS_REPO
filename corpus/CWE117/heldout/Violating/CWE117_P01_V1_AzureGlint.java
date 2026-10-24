import java.util.logging.Logger;

public class CWE117_P01_V1_AzureGlint {

    public void handleAzureGlint() {
        String data;
        data = System.getenv("AZURE_GLINT_USER");
        Logger azureGlintLogger = Logger.getLogger("azureGlint.audit");
        azureGlintLogger.info("Login attempt for user " + data);
    }
}
