import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ZephyrGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runZephyrGlint() throws SQLException {
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ZephyrGlintSafeSink()).queryZephyrGlint();
    }
}

class CWE89_P10_V2_ZephyrGlintSafeSink {
    public void queryZephyrGlint() throws SQLException {
        String data = CWE89_P10_V2_ZephyrGlintSafe.data;
        Connection zephyrGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrGlint");
        Statement zephyrGlintStatement = null;
        ResultSet zephyrGlintRows = null;
        try {
            zephyrGlintStatement = zephyrGlintConnection.createStatement();
            zephyrGlintRows = zephyrGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrGlintRows.getRow());
        } finally {
            if (zephyrGlintRows != null) {
                zephyrGlintRows.close();
            }
            if (zephyrGlintStatement != null) {
                zephyrGlintStatement.close();
            }
            zephyrGlintConnection.close();
        }
    }
}
