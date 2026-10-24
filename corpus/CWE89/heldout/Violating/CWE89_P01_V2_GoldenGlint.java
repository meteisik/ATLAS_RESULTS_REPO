import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_GoldenGlint {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runGoldenGlint() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("GOLDEN_GLINT_FILTER");
        } else {
            data = null;
        }
        Connection goldenGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenGlint");
        Statement goldenGlintStatement = null;
        ResultSet goldenGlintRows = null;
        try {
            goldenGlintStatement = goldenGlintConnection.createStatement();
            goldenGlintRows = goldenGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenGlintRows.getRow());
        } finally {
            if (goldenGlintRows != null) {
                goldenGlintRows.close();
            }
            if (goldenGlintStatement != null) {
                goldenGlintStatement.close();
            }
            goldenGlintConnection.close();
        }
    }
}
