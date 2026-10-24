import java.util.logging.Logger;

public class CWE117_P10_V2_AzureGlint {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public void handleAzureGlint() {
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_GLINT_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AzureGlintSink()).logAzureGlint();
    }
}

class CWE117_P10_V2_AzureGlintSink {
    public void logAzureGlint() {
        String data = CWE117_P10_V2_AzureGlint.data;
        Logger azureGlintLogger = Logger.getLogger("azureGlint.audit");
        azureGlintLogger.info("Login attempt for user " + data);
    }
}
