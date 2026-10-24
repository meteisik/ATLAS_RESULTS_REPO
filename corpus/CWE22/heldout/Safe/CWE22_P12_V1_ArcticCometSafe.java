import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ArcticCometSafe {

    public void openArcticComet() {
        String data;
        data = "foo";
        CWE22_P12_V1_ArcticCometSafeBase baseObject = new CWE22_P12_V1_ArcticCometSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ArcticCometSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ArcticCometSafeSink extends CWE22_P12_V1_ArcticCometSafeBase {
    public void action(String data) {
        String arcticCometRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticCometFile = new File(arcticCometRoot + data);
            FileInputStream arcticCometStream = null;
            InputStreamReader arcticCometStreamReader = null;
            BufferedReader arcticCometReader = null;
            if (arcticCometFile.exists() && arcticCometFile.isFile()) {
                try {
                    arcticCometStream = new FileInputStream(arcticCometFile);
                    arcticCometStreamReader = new InputStreamReader(arcticCometStream, "UTF-8");
                    arcticCometReader = new BufferedReader(arcticCometStreamReader);
                    System.out.println(arcticCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_ArcticCometSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticCometReader != null) {
                            arcticCometReader.close();
                        }
                        if (arcticCometStreamReader != null) {
                            arcticCometStreamReader.close();
                        }
                        if (arcticCometStream != null) {
                            arcticCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_ArcticCometSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
