import java.util.logging.Logger;

public class CWE117_P12_V2_AzureFlareSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleAzureFlare() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("AZURE_FLARE_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_AzureFlareSafeBase baseObject = new CWE117_P12_V2_AzureFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureFlareSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureFlareSafeSink extends CWE117_P12_V2_AzureFlareSafeBase {
    public void action(String data) {
        Logger azureFlareLogger = Logger.getLogger("azureFlare.audit");
        azureFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
