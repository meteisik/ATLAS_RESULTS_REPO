import java.util.logging.Logger;

public class CWE117_P12_V2_AzureGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleAzureGlint() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AZURE_GLINT_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_AzureGlintSafeBase baseObject = new CWE117_P12_V2_AzureGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureGlintSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureGlintSafeSink extends CWE117_P12_V2_AzureGlintSafeBase {
    public void action(String data) {
        Logger azureGlintLogger = Logger.getLogger("azureGlint.audit");
        azureGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
