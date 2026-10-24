import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SaffronGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronGlint() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SaffronGlintSafeSink()).querySaffronGlint(data);
    }
}

class CWE89_P06_V2_SaffronGlintSafeSink {
    public void querySaffronGlint(String data) throws SQLException {
        Connection saffronGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronGlint");
        Statement saffronGlintStatement = null;
        ResultSet saffronGlintRows = null;
        try {
            saffronGlintStatement = saffronGlintConnection.createStatement();
            saffronGlintRows = saffronGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronGlintRows.getRow());
        } finally {
            if (saffronGlintRows != null) {
                saffronGlintRows.close();
            }
            if (saffronGlintStatement != null) {
                saffronGlintStatement.close();
            }
            saffronGlintConnection.close();
        }
    }
}
