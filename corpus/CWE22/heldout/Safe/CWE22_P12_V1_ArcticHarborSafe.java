import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ArcticHarborSafe {

    public void openArcticHarbor() {
        String data;
        data = "foo";
        CWE22_P12_V1_ArcticHarborSafeBase baseObject = new CWE22_P12_V1_ArcticHarborSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ArcticHarborSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ArcticHarborSafeSink extends CWE22_P12_V1_ArcticHarborSafeBase {
    public void action(String data) {
        String arcticHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticHarborFile = new File(arcticHarborRoot + data);
            FileInputStream arcticHarborStream = null;
            InputStreamReader arcticHarborStreamReader = null;
            BufferedReader arcticHarborReader = null;
            if (arcticHarborFile.exists() && arcticHarborFile.isFile()) {
                try {
                    arcticHarborStream = new FileInputStream(arcticHarborFile);
                    arcticHarborStreamReader = new InputStreamReader(arcticHarborStream, "UTF-8");
                    arcticHarborReader = new BufferedReader(arcticHarborStreamReader);
                    System.out.println(arcticHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_ArcticHarborSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticHarborReader != null) {
                            arcticHarborReader.close();
                        }
                        if (arcticHarborStreamReader != null) {
                            arcticHarborStreamReader.close();
                        }
                        if (arcticHarborStream != null) {
                            arcticHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_ArcticHarborSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
