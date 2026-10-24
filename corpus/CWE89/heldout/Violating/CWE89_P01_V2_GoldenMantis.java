import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_GoldenMantis {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runGoldenMantis() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("GOLDEN_MANTIS_FILTER");
        } else {
            data = null;
        }
        Connection goldenMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenMantis");
        Statement goldenMantisStatement = null;
        ResultSet goldenMantisRows = null;
        try {
            goldenMantisStatement = goldenMantisConnection.createStatement();
            goldenMantisRows = goldenMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenMantisRows.getRow());
        } finally {
            if (goldenMantisRows != null) {
                goldenMantisRows.close();
            }
            if (goldenMantisStatement != null) {
                goldenMantisStatement.close();
            }
            goldenMantisConnection.close();
        }
    }
}
