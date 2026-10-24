import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_GoldenFlare {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runGoldenFlare() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("GOLDEN_FLARE_FILTER");
        } else {
            data = null;
        }
        Connection goldenFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenFlare");
        Statement goldenFlareStatement = null;
        ResultSet goldenFlareRows = null;
        try {
            goldenFlareStatement = goldenFlareConnection.createStatement();
            goldenFlareRows = goldenFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenFlareRows.getRow());
        } finally {
            if (goldenFlareRows != null) {
                goldenFlareRows.close();
            }
            if (goldenFlareStatement != null) {
                goldenFlareStatement.close();
            }
            goldenFlareConnection.close();
        }
    }
}
