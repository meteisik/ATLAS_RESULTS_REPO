import java.util.logging.Logger;

public class CWE117_P01_V1_AzureGlintSafe {

    public void handleAzureGlint() {
        String data;
        data = System.getenv("AZURE_GLINT_USER");
        Logger azureGlintLogger = Logger.getLogger("azureGlint.audit");
        azureGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
