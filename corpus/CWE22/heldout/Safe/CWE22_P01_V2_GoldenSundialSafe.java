import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V2_GoldenSundialSafe {

    public void openGoldenSundial() {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        String goldenSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenSundialFile = new File(goldenSundialRoot + data);
            FileInputStream goldenSundialStream = null;
            InputStreamReader goldenSundialStreamReader = null;
            BufferedReader goldenSundialReader = null;
            if (goldenSundialFile.exists() && goldenSundialFile.isFile()) {
                try {
                    goldenSundialStream = new FileInputStream(goldenSundialFile);
                    goldenSundialStreamReader = new InputStreamReader(goldenSundialStream, "UTF-8");
                    goldenSundialReader = new BufferedReader(goldenSundialStreamReader);
                    System.out.println(goldenSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V2_GoldenSundialSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenSundialReader != null) {
                            goldenSundialReader.close();
                        }
                        if (goldenSundialStreamReader != null) {
                            goldenSundialStreamReader.close();
                        }
                        if (goldenSundialStream != null) {
                            goldenSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V2_GoldenSundialSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
