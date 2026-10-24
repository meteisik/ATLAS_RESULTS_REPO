import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V1_GoldenQuartzSafe {

    private String locateGoldenQuartz() {
        String data;
        data = "foo";
        return data;
    }

    public void openGoldenQuartz() {
        String data = locateGoldenQuartz();
        String goldenQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenQuartzFile = new File(goldenQuartzRoot + data);
            FileInputStream goldenQuartzStream = null;
            InputStreamReader goldenQuartzStreamReader = null;
            BufferedReader goldenQuartzReader = null;
            if (goldenQuartzFile.exists() && goldenQuartzFile.isFile()) {
                try {
                    goldenQuartzStream = new FileInputStream(goldenQuartzFile);
                    goldenQuartzStreamReader = new InputStreamReader(goldenQuartzStream, "UTF-8");
                    goldenQuartzReader = new BufferedReader(goldenQuartzStreamReader);
                    System.out.println(goldenQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V1_GoldenQuartzSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenQuartzReader != null) {
                            goldenQuartzReader.close();
                        }
                        if (goldenQuartzStreamReader != null) {
                            goldenQuartzStreamReader.close();
                        }
                        if (goldenQuartzStream != null) {
                            goldenQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V1_GoldenQuartzSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
