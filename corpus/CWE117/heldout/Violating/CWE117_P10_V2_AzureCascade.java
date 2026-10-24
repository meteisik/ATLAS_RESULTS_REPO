import java.util.logging.Logger;

public class CWE117_P10_V2_AzureCascade {
    private static boolean privateTrue = true;

    public static String data;

    public void handleAzureCascade() {
        if (privateTrue) {
            data = System.getenv("AZURE_CASCADE_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AzureCascadeSink()).logAzureCascade();
    }
}

class CWE117_P10_V2_AzureCascadeSink {
    public void logAzureCascade() {
        String data = CWE117_P10_V2_AzureCascade.data;
        Logger azureCascadeLogger = Logger.getLogger("azureCascade.audit");
        azureCascadeLogger.info("Login attempt for user " + data);
    }
}
