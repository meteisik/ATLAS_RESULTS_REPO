import java.util.logging.Logger;

public class CWE117_P10_V2_AzureGlintSafe {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public void handleAzureGlint() {
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_GLINT_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AzureGlintSafeSink()).logAzureGlint();
    }
}

class CWE117_P10_V2_AzureGlintSafeSink {
    public void logAzureGlint() {
        String data = CWE117_P10_V2_AzureGlintSafe.data;
        Logger azureGlintLogger = Logger.getLogger("azureGlint.audit");
        azureGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
