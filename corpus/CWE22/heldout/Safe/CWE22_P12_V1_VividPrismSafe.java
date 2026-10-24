import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_VividPrismSafe {

    public void openVividPrism() {
        String data;
        data = "foo";
        CWE22_P12_V1_VividPrismSafeBase baseObject = new CWE22_P12_V1_VividPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_VividPrismSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_VividPrismSafeSink extends CWE22_P12_V1_VividPrismSafeBase {
    public void action(String data) {
        String vividPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File vividPrismFile = new File(vividPrismRoot + data);
            FileInputStream vividPrismStream = null;
            InputStreamReader vividPrismStreamReader = null;
            BufferedReader vividPrismReader = null;
            if (vividPrismFile.exists() && vividPrismFile.isFile()) {
                try {
                    vividPrismStream = new FileInputStream(vividPrismFile);
                    vividPrismStreamReader = new InputStreamReader(vividPrismStream, "UTF-8");
                    vividPrismReader = new BufferedReader(vividPrismStreamReader);
                    System.out.println(vividPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_VividPrismSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividPrismReader != null) {
                            vividPrismReader.close();
                        }
                        if (vividPrismStreamReader != null) {
                            vividPrismStreamReader.close();
                        }
                        if (vividPrismStream != null) {
                            vividPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_VividPrismSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
