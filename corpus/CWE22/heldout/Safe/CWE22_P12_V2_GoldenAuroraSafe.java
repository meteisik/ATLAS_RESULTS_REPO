import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_GoldenAuroraSafe {

    public void openGoldenAurora() {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE22_P12_V2_GoldenAuroraSafeBase baseObject = new CWE22_P12_V2_GoldenAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_GoldenAuroraSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_GoldenAuroraSafeSink extends CWE22_P12_V2_GoldenAuroraSafeBase {
    public void action(String data) {
        String goldenAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenAuroraFile = new File(goldenAuroraRoot + data);
            FileInputStream goldenAuroraStream = null;
            InputStreamReader goldenAuroraStreamReader = null;
            BufferedReader goldenAuroraReader = null;
            if (goldenAuroraFile.exists() && goldenAuroraFile.isFile()) {
                try {
                    goldenAuroraStream = new FileInputStream(goldenAuroraFile);
                    goldenAuroraStreamReader = new InputStreamReader(goldenAuroraStream, "UTF-8");
                    goldenAuroraReader = new BufferedReader(goldenAuroraStreamReader);
                    System.out.println(goldenAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_GoldenAuroraSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenAuroraReader != null) {
                            goldenAuroraReader.close();
                        }
                        if (goldenAuroraStreamReader != null) {
                            goldenAuroraStreamReader.close();
                        }
                        if (goldenAuroraStream != null) {
                            goldenAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_GoldenAuroraSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
