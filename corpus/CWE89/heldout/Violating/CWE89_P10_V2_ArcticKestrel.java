import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ArcticKestrel {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runArcticKestrel() throws SQLException {
        if (IO.staticFive == 5) {
            data = System.getenv("ARCTIC_KESTREL_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ArcticKestrelSink()).queryArcticKestrel();
    }
}

class CWE89_P10_V2_ArcticKestrelSink {
    public void queryArcticKestrel() throws SQLException {
        String data = CWE89_P10_V2_ArcticKestrel.data;
        Connection arcticKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticKestrel");
        Statement arcticKestrelStatement = null;
        ResultSet arcticKestrelRows = null;
        try {
            arcticKestrelStatement = arcticKestrelConnection.createStatement();
            arcticKestrelRows = arcticKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticKestrelRows.getRow());
        } finally {
            if (arcticKestrelRows != null) {
                arcticKestrelRows.close();
            }
            if (arcticKestrelStatement != null) {
                arcticKestrelStatement.close();
            }
            arcticKestrelConnection.close();
        }
    }
}
