import java.util.logging.Logger;

public class CWE117_P01_V1_AzureCipher {

    public void handleAzureCipher() {
        String data;
        data = System.getenv("AZURE_CIPHER_USER");
        Logger azureCipherLogger = Logger.getLogger("azureCipher.audit");
        azureCipherLogger.info("Login attempt for user " + data);
    }
}
