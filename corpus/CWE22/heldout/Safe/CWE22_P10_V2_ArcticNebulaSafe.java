import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_ArcticNebulaSafe {
    public static String data;

    public void openArcticNebula() {
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        (new CWE22_P10_V2_ArcticNebulaSafeSink()).readArcticNebula();
    }
}

class CWE22_P10_V2_ArcticNebulaSafeSink {
    public void readArcticNebula() {
        String data = CWE22_P10_V2_ArcticNebulaSafe.data;
        String arcticNebulaRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticNebulaFile = new File(arcticNebulaRoot + data);
            FileInputStream arcticNebulaStream = null;
            InputStreamReader arcticNebulaStreamReader = null;
            BufferedReader arcticNebulaReader = null;
            if (arcticNebulaFile.exists() && arcticNebulaFile.isFile()) {
                try {
                    arcticNebulaStream = new FileInputStream(arcticNebulaFile);
                    arcticNebulaStreamReader = new InputStreamReader(arcticNebulaStream, "UTF-8");
                    arcticNebulaReader = new BufferedReader(arcticNebulaStreamReader);
                    System.out.println(arcticNebulaReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_ArcticNebulaSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticNebulaReader != null) {
                            arcticNebulaReader.close();
                        }
                        if (arcticNebulaStreamReader != null) {
                            arcticNebulaStreamReader.close();
                        }
                        if (arcticNebulaStream != null) {
                            arcticNebulaStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_ArcticNebulaSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
