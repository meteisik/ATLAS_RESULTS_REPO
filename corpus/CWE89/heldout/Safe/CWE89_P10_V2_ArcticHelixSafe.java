import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ArcticHelixSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runArcticHelix() throws SQLException {
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ArcticHelixSafeSink()).queryArcticHelix();
    }
}

class CWE89_P10_V2_ArcticHelixSafeSink {
    public void queryArcticHelix() throws SQLException {
        String data = CWE89_P10_V2_ArcticHelixSafe.data;
        Connection arcticHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHelix");
        Statement arcticHelixStatement = null;
        ResultSet arcticHelixRows = null;
        try {
            arcticHelixStatement = arcticHelixConnection.createStatement();
            arcticHelixRows = arcticHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticHelixRows.getRow());
        } finally {
            if (arcticHelixRows != null) {
                arcticHelixRows.close();
            }
            if (arcticHelixStatement != null) {
                arcticHelixStatement.close();
            }
            arcticHelixConnection.close();
        }
    }
}
