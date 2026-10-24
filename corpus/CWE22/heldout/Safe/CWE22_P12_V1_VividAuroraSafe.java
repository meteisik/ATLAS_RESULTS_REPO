import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_VividAuroraSafe {

    public void openVividAurora() {
        String data;
        data = "foo";
        CWE22_P12_V1_VividAuroraSafeBase baseObject = new CWE22_P12_V1_VividAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_VividAuroraSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_VividAuroraSafeSink extends CWE22_P12_V1_VividAuroraSafeBase {
    public void action(String data) {
        String vividAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File vividAuroraFile = new File(vividAuroraRoot + data);
            FileInputStream vividAuroraStream = null;
            InputStreamReader vividAuroraStreamReader = null;
            BufferedReader vividAuroraReader = null;
            if (vividAuroraFile.exists() && vividAuroraFile.isFile()) {
                try {
                    vividAuroraStream = new FileInputStream(vividAuroraFile);
                    vividAuroraStreamReader = new InputStreamReader(vividAuroraStream, "UTF-8");
                    vividAuroraReader = new BufferedReader(vividAuroraStreamReader);
                    System.out.println(vividAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_VividAuroraSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividAuroraReader != null) {
                            vividAuroraReader.close();
                        }
                        if (vividAuroraStreamReader != null) {
                            vividAuroraStreamReader.close();
                        }
                        if (vividAuroraStream != null) {
                            vividAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_VividAuroraSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
