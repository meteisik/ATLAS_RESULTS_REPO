import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V1_GoldenMantis {

    private String locateGoldenMantis() {
        String data;
        data = System.getenv("GOLDEN_MANTIS_PATH");
        return data;
    }

    public void openGoldenMantis() {
        String data = locateGoldenMantis();
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
                    Logger.getLogger("CWE22_P04_V1_GoldenMantis").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P04_V1_GoldenMantis").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
