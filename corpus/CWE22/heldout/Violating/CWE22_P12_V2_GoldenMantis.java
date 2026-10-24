import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_GoldenMantis {
    private static boolean privateReturnsTrue() { return true; }

    public void openGoldenMantis() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("GOLDEN_MANTIS_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_GoldenMantisBase baseObject = new CWE22_P12_V2_GoldenMantisSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_GoldenMantisBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_GoldenMantisSink extends CWE22_P12_V2_GoldenMantisBase {
    public void action(String data) {
        String goldenMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenMantisFile = new File(goldenMantisRoot + data);
            FileInputStream goldenMantisStream = null;
            InputStreamReader goldenMantisStreamReader = null;
            BufferedReader goldenMantisReader = null;
            if (goldenMantisFile.exists() && goldenMantisFile.isFile()) {
                try {
                    goldenMantisStream = new FileInputStream(goldenMantisFile);
                    goldenMantisStreamReader = new InputStreamReader(goldenMantisStream, "UTF-8");
                    goldenMantisReader = new BufferedReader(goldenMantisStreamReader);
                    System.out.println(goldenMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_GoldenMantisSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenMantisReader != null) {
                            goldenMantisReader.close();
                        }
                        if (goldenMantisStreamReader != null) {
                            goldenMantisStreamReader.close();
                        }
                        if (goldenMantisStream != null) {
                            goldenMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_GoldenMantisSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
