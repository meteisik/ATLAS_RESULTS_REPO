import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetCipher {

    public void handleVelvetCipher() {
        String data;
        data = System.getenv("VELVET_CIPHER_USER");
        CWE117_P12_V1_VelvetCipherBase baseObject = new CWE117_P12_V1_VelvetCipherSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetCipherBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetCipherSink extends CWE117_P12_V1_VelvetCipherBase {
    public void action(String data) {
        Logger velvetCipherLogger = Logger.getLogger("velvetCipher.audit");
        velvetCipherLogger.info("Login attempt for user " + data);
    }
}
