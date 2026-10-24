import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V1_AmberQuartz {

    public void openAmberQuartz() {
        String data;
        data = System.getenv("AMBER_QUARTZ_PATH");
        String amberQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File amberQuartzFile = new File(amberQuartzRoot + data);
            FileInputStream amberQuartzStream = null;
            InputStreamReader amberQuartzStreamReader = null;
            BufferedReader amberQuartzReader = null;
            if (amberQuartzFile.exists() && amberQuartzFile.isFile()) {
                try {
                    amberQuartzStream = new FileInputStream(amberQuartzFile);
                    amberQuartzStreamReader = new InputStreamReader(amberQuartzStream, "UTF-8");
                    amberQuartzReader = new BufferedReader(amberQuartzStreamReader);
                    System.out.println(amberQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V1_AmberQuartz").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberQuartzReader != null) {
                            amberQuartzReader.close();
                        }
                        if (amberQuartzStreamReader != null) {
                            amberQuartzStreamReader.close();
                        }
                        if (amberQuartzStream != null) {
                            amberQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V1_AmberQuartz").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
