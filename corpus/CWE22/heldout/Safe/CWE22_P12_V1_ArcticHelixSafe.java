import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ArcticHelixSafe {

    public void openArcticHelix() {
        String data;
        data = "foo";
        CWE22_P12_V1_ArcticHelixSafeBase baseObject = new CWE22_P12_V1_ArcticHelixSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ArcticHelixSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ArcticHelixSafeSink extends CWE22_P12_V1_ArcticHelixSafeBase {
    public void action(String data) {
        String arcticHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticHelixFile = new File(arcticHelixRoot + data);
            FileInputStream arcticHelixStream = null;
            InputStreamReader arcticHelixStreamReader = null;
            BufferedReader arcticHelixReader = null;
            if (arcticHelixFile.exists() && arcticHelixFile.isFile()) {
                try {
                    arcticHelixStream = new FileInputStream(arcticHelixFile);
                    arcticHelixStreamReader = new InputStreamReader(arcticHelixStream, "UTF-8");
                    arcticHelixReader = new BufferedReader(arcticHelixStreamReader);
                    System.out.println(arcticHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_ArcticHelixSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticHelixReader != null) {
                            arcticHelixReader.close();
                        }
                        if (arcticHelixStreamReader != null) {
                            arcticHelixStreamReader.close();
                        }
                        if (arcticHelixStream != null) {
                            arcticHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_ArcticHelixSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
