import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ArcticHarborSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runArcticHarbor() throws SQLException {
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ArcticHarborSafeSink()).queryArcticHarbor();
    }
}

class CWE89_P10_V2_ArcticHarborSafeSink {
    public void queryArcticHarbor() throws SQLException {
        String data = CWE89_P10_V2_ArcticHarborSafe.data;
        Connection arcticHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHarbor");
        Statement arcticHarborStatement = null;
        ResultSet arcticHarborRows = null;
        try {
            arcticHarborStatement = arcticHarborConnection.createStatement();
            arcticHarborRows = arcticHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticHarborRows.getRow());
        } finally {
            if (arcticHarborRows != null) {
                arcticHarborRows.close();
            }
            if (arcticHarborStatement != null) {
                arcticHarborStatement.close();
            }
            arcticHarborConnection.close();
        }
    }
}
