import java.util.logging.Logger;

public class CWE117_P02_V1_AzureGlint {

    public void handleAzureGlint() {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_GLINT_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger azureGlintLogger = Logger.getLogger("azureGlint.audit");
            azureGlintLogger.info("Login attempt for user " + data);
        }
    }
}
