import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ZephyrPrismSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runZephyrPrism() throws SQLException {
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ZephyrPrismSafeSink()).queryZephyrPrism();
    }
}

class CWE89_P10_V2_ZephyrPrismSafeSink {
    public void queryZephyrPrism() throws SQLException {
        String data = CWE89_P10_V2_ZephyrPrismSafe.data;
        Connection zephyrPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrPrism");
        Statement zephyrPrismStatement = null;
        ResultSet zephyrPrismRows = null;
        try {
            zephyrPrismStatement = zephyrPrismConnection.createStatement();
            zephyrPrismRows = zephyrPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrPrismRows.getRow());
        } finally {
            if (zephyrPrismRows != null) {
                zephyrPrismRows.close();
            }
            if (zephyrPrismStatement != null) {
                zephyrPrismStatement.close();
            }
            zephyrPrismConnection.close();
        }
    }
}
